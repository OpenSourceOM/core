// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type collectedPod struct {
	id     string
	labels map[string]string
}

type collectedService struct {
	id       string
	name     string
	selector map[string]string
	public   bool
}

type ingressBackend struct {
	id   string
	name string
}

type describedPolicy struct {
	name           string
	selector       labels.Selector
	governsIngress bool
	allowsWorld    bool
}

// serviceExposesInternet reports whether the service type itself publishes
// selected pods. A NodePort stays on the node network until an Ingress
// publishes the service.
func serviceExposesInternet(serviceType string) bool {
	return serviceType == string(corev1.ServiceTypeLoadBalancer)
}

func serviceSelectsPod(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(podLabels))
}

// linkExposure records Ingress objects and REACHABLE edges. A pod is reachable
// when a LoadBalancer or an Ingress backend selects it, unless a NetworkPolicy
// selects that pod and does not allow ingress from the world.
func (c *Collector) linkExposure(batch *graph.Batch, pods []collectedPod, services []collectedService, ingresses []*networkingv1.Ingress, policies []*networkingv1.NetworkPolicy) error {
	described, err := describePolicies(policies)
	if err != nil {
		return err
	}
	backends := c.recordIngresses(batch, ingresses)
	c.linkPods(batch, pods, services, backends, described)
	return nil
}

func (c *Collector) recordIngresses(batch *graph.Batch, ingresses []*networkingv1.Ingress) map[string][]ingressBackend {
	backends := map[string][]ingressBackend{}
	for _, ing := range ingresses {
		if ing == nil || ing.Name == "" || ing.Namespace == "" {
			continue
		}
		id := c.nodeID("network", ing.Namespace+"/ingress/"+ing.Name)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        id,
			Type:      graph.NodeNetwork,
			Name:      ing.Name,
			Provider:  "kubernetes",
			AccountID: c.Cluster,
			Properties: graph.MustProperties(map[string]any{
				"namespace":       ing.Namespace,
				"kind":            "Ingress",
				"internet_facing": true,
			}),
		})
		backend := ingressBackend{id: id, name: ing.Name}
		for _, serviceName := range ingressServiceNames(ing) {
			backends[serviceName] = append(backends[serviceName], backend)
		}
	}
	return backends
}

func ingressServiceNames(ing *networkingv1.Ingress) []string {
	if ing == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		add(ing.Spec.DefaultBackend.Service.Name)
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				add(path.Backend.Service.Name)
			}
		}
	}
	return names
}

func describePolicies(policies []*networkingv1.NetworkPolicy) ([]describedPolicy, error) {
	described := make([]describedPolicy, 0, len(policies))
	for _, pol := range policies {
		if pol == nil || pol.Name == "" {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("network policy %s: %w", pol.Name, err)
		}
		described = append(described, describedPolicy{
			name:           pol.Name,
			selector:       selector,
			governsIngress: policyGovernsIngress(pol.Spec),
			allowsWorld:    policyAllowsWorld(pol.Spec),
		})
	}
	return described, nil
}

func policyGovernsIngress(spec networkingv1.NetworkPolicySpec) bool {
	if len(spec.PolicyTypes) == 0 {
		return true
	}
	for _, policyType := range spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

// policyAllowsWorld reports whether any ingress rule admits traffic from
// outside the cluster. An empty From allows every source. Pod and namespace
// selectors only admit in-cluster traffic. An ipBlock allows the world when
// it is 0.0.0.0/0 or ::/0 with no exceptions.
func policyAllowsWorld(spec networkingv1.NetworkPolicySpec) bool {
	for _, rule := range spec.Ingress {
		if len(rule.From) == 0 {
			return true
		}
		for _, peer := range rule.From {
			if peer.IPBlock != nil && ipBlockAllowsWorld(peer.IPBlock) {
				return true
			}
		}
	}
	return false
}

func ipBlockAllowsWorld(block *networkingv1.IPBlock) bool {
	if block == nil || len(block.Except) > 0 {
		return false
	}
	cidr := strings.TrimSpace(block.CIDR)
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

func (c *Collector) linkPods(batch *graph.Batch, pods []collectedPod, services []collectedService, backends map[string][]ingressBackend, policies []describedPolicy) {
	reachable := map[string]string{}
	for _, pod := range pods {
		selecting := policiesSelecting(policies, pod.labels)
		if len(selecting) > 0 {
			setNodeProperty(batch, pod.id, "network_policy", strings.Join(selecting, ","))
		}
		blocked := ingressBlocked(policies, pod.labels)

		linkedIngress := map[string]struct{}{}
		for _, svc := range services {
			if !serviceSelectsPod(svc.selector, pod.labels) {
				continue
			}
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(pod.id, svc.id, graph.EdgeAffects),
				SourceID: pod.id,
				TargetID: svc.id,
				Type:     graph.EdgeAffects,
				Properties: graph.MustProperties(map[string]any{
					"via": "service selector",
				}),
			})
			via := ""
			if svc.public {
				via = svc.name
			}
			for _, backend := range backends[svc.name] {
				if _, seen := linkedIngress[backend.id]; !seen {
					linkedIngress[backend.id] = struct{}{}
					batch.Edges = append(batch.Edges, graph.Edge{
						ID:       c.edgeID(pod.id, backend.id, graph.EdgeAffects),
						SourceID: pod.id,
						TargetID: backend.id,
						Type:     graph.EdgeAffects,
						Properties: graph.MustProperties(map[string]any{
							"via": "ingress",
						}),
					})
				}
				if via == "" {
					via = backend.name
				}
			}
			if !blocked && via != "" && reachable[pod.id] == "" {
				reachable[pod.id] = via
			}
		}
	}
	for podID, via := range reachable {
		batch.Edges = append(batch.Edges, graph.Edge{
			ID:       c.edgeID(graph.InternetNodeID, podID, graph.EdgeReachable),
			SourceID: graph.InternetNodeID,
			TargetID: podID,
			Type:     graph.EdgeReachable,
			Properties: graph.MustProperties(map[string]any{
				"via": via,
			}),
		})
	}
}

func policiesSelecting(policies []describedPolicy, podLabels map[string]string) []string {
	var names []string
	for _, pol := range policies {
		if pol.selector != nil && pol.selector.Matches(labels.Set(podLabels)) {
			names = append(names, pol.name)
		}
	}
	sort.Strings(names)
	return names
}

func ingressBlocked(policies []describedPolicy, podLabels map[string]string) bool {
	governs := false
	allows := false
	for _, pol := range policies {
		if pol.selector == nil || !pol.selector.Matches(labels.Set(podLabels)) {
			continue
		}
		if !pol.governsIngress {
			continue
		}
		governs = true
		if pol.allowsWorld {
			allows = true
		}
	}
	return governs && !allows
}

func setNodeProperty(batch *graph.Batch, id, key string, value any) {
	for i := range batch.Nodes {
		if batch.Nodes[i].ID != id {
			continue
		}
		if batch.Nodes[i].Properties == nil {
			batch.Nodes[i].Properties = map[string]any{}
		}
		batch.Nodes[i].Properties[key] = value
		return
	}
}
