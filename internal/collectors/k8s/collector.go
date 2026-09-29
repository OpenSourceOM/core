// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"fmt"
	"os"

	"github.com/OpenSourceOM/core/internal/graph"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Collector struct {
	Cluster   string
	Namespace string
}

func NewCollector(cluster, namespace string) *Collector {
	return &Collector{Cluster: cluster, Namespace: namespace}
}

func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return graph.Batch{}, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return graph.Batch{}, fmt.Errorf("kubernetes client: %w", err)
	}

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:       graph.InternetNodeID,
				Type:     graph.NodeInternet,
				Name:     "Internet",
				Provider: "kubernetes",
			},
			{
				ID:        c.nodeID("control", "cluster"),
				Type:      graph.NodeControl,
				Name:      c.Cluster,
				Provider:  "kubernetes",
				AccountID: c.Cluster,
				Properties: graph.MustProperties(map[string]any{
					"resource_id": c.Cluster,
				}),
			},
		},
	}

	namespaces, err := c.listNamespaces(ctx, client)
	if err != nil {
		return graph.Batch{}, err
	}

	for _, ns := range namespaces {
		nsID := c.nodeID("network", ns)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        nsID,
			Type:      graph.NodeNetwork,
			Name:      ns,
			Provider:  "kubernetes",
			AccountID: c.Cluster,
			Properties: graph.MustProperties(map[string]any{
				"namespace": ns,
			}),
		})

		pods, err := c.collectPods(ctx, client, ns, nsID, &batch)
		if err != nil {
			return graph.Batch{}, err
		}
		if err := c.collectServiceAccounts(ctx, client, ns, &batch); err != nil {
			return graph.Batch{}, err
		}
		services, err := c.collectServices(ctx, client, ns, &batch)
		if err != nil {
			return graph.Batch{}, err
		}
		ingresses, err := c.listIngresses(ctx, client, ns)
		if err != nil {
			return graph.Batch{}, err
		}
		policies, err := c.listNetworkPolicies(ctx, client, ns)
		if err != nil {
			return graph.Batch{}, err
		}
		if err := c.linkExposure(&batch, pods, services, ingresses, policies); err != nil {
			return graph.Batch{}, fmt.Errorf("link exposure in %s: %w", ns, err)
		}
	}

	return batch, nil
}

func (c *Collector) listNamespaces(ctx context.Context, client *kubernetes.Clientset) ([]string, error) {
	if c.Namespace != "" {
		return []string{c.Namespace}, nil
	}
	out, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	namespaces := make([]string, 0, len(out.Items))
	for _, item := range out.Items {
		namespaces = append(namespaces, item.Name)
	}
	return namespaces, nil
}

func (c *Collector) collectPods(ctx context.Context, client *kubernetes.Clientset, namespace, nsID string, batch *graph.Batch) ([]collectedPod, error) {
	out, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", namespace, err)
	}
	pods := make([]collectedPod, 0, len(out.Items))
	for _, pod := range out.Items {
		workloadID := c.nodeID("workload", namespace+"/"+pod.Name)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        workloadID,
			Type:      graph.NodeWorkload,
			Name:      pod.Name,
			Provider:  "kubernetes",
			AccountID: c.Cluster,
			Properties: graph.MustProperties(map[string]any{
				"namespace": namespace,
				"phase":     string(pod.Status.Phase),
				"node":      pod.Spec.NodeName,
			}),
		})
		batch.Edges = append(batch.Edges, graph.Edge{
			ID:       c.edgeID(workloadID, nsID, graph.EdgeAffects),
			SourceID: workloadID,
			TargetID: nsID,
			Type:     graph.EdgeAffects,
		})

		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		saID := c.nodeID("identity", namespace+"/"+saName)
		batch.Edges = append(batch.Edges, graph.Edge{
			ID:       c.edgeID(saID, workloadID, graph.EdgeAssumes),
			SourceID: saID,
			TargetID: workloadID,
			Type:     graph.EdgeAssumes,
		})
		pods = append(pods, collectedPod{id: workloadID, labels: pod.Labels})
	}
	return pods, nil
}

func (c *Collector) collectServiceAccounts(ctx context.Context, client *kubernetes.Clientset, namespace string, batch *graph.Batch) error {
	out, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list service accounts in %s: %w", namespace, err)
	}
	for _, sa := range out.Items {
		saID := c.nodeID("identity", namespace+"/"+sa.Name)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        saID,
			Type:      graph.NodeIdentity,
			Name:      sa.Name,
			Provider:  "kubernetes",
			AccountID: c.Cluster,
			Properties: graph.MustProperties(map[string]any{
				"namespace": namespace,
			}),
		})
	}
	return nil
}

func (c *Collector) collectServices(ctx context.Context, client *kubernetes.Clientset, namespace string, batch *graph.Batch) ([]collectedService, error) {
	out, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services in %s: %w", namespace, err)
	}
	services := make([]collectedService, 0, len(out.Items))
	for _, svc := range out.Items {
		netID := c.nodeID("network", namespace+"/service/"+svc.Name)
		public := serviceExposesInternet(string(svc.Spec.Type))
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        netID,
			Type:      graph.NodeNetwork,
			Name:      svc.Name,
			Provider:  "kubernetes",
			AccountID: c.Cluster,
			Properties: graph.MustProperties(map[string]any{
				"namespace":       namespace,
				"service_type":    string(svc.Spec.Type),
				"internet_facing": public,
			}),
		})
		services = append(services, collectedService{
			id:       netID,
			name:     svc.Name,
			selector: svc.Spec.Selector,
			public:   public,
		})
	}
	return services, nil
}

func (c *Collector) listIngresses(ctx context.Context, client *kubernetes.Clientset, namespace string) ([]*networkingv1.Ingress, error) {
	out, err := client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses in %s: %w", namespace, err)
	}
	items := make([]*networkingv1.Ingress, 0, len(out.Items))
	for i := range out.Items {
		items = append(items, &out.Items[i])
	}
	return items, nil
}

func (c *Collector) listNetworkPolicies(ctx context.Context, client *kubernetes.Clientset, namespace string) ([]*networkingv1.NetworkPolicy, error) {
	out, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list network policies in %s: %w", namespace, err)
	}
	items := make([]*networkingv1.NetworkPolicy, 0, len(out.Items))
	for i := range out.Items {
		items = append(items, &out.Items[i])
	}
	return items, nil
}

// loadConfig prefers KUBECONFIG when the operator set it. A pod with no
// kubeconfig uses its service account. Cluster stays the graph account id
// in that case, rather than a kubeconfig context name.
func (c *Collector) loadConfig() (*rest.Config, error) {
	if os.Getenv("KUBECONFIG") != "" {
		return c.kubeConfig()
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		return rest.InClusterConfig()
	}
	return c.kubeConfig()
}

func (c *Collector) kubeConfig() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	if c.Cluster != "" && c.Cluster != "default" {
		configOverrides.CurrentContext = c.Cluster
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
}

func (c *Collector) nodeID(kind, resource string) string {
	return fmt.Sprintf("k8s:%s:%s:%s", c.Cluster, kind, resource)
}

func (c *Collector) edgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, edgeType)
}
