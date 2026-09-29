// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceExposureSelectsPods(t *testing.T) {
	c := NewCollector("demo", "apps")
	privateID := c.nodeID("workload", "apps/private")
	webID := c.nodeID("workload", "apps/web")
	internalID := c.nodeID("workload", "apps/internal")
	lbID := c.nodeID("network", "apps/service/web")
	clusterID := c.nodeID("network", "apps/service/internal")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: privateID, labels: map[string]string{"app.kubernetes.io/name": "private"}},
		{id: webID, labels: map[string]string{"app": "web"}},
		{id: internalID, labels: map[string]string{"app": "internal"}},
	}, []collectedService{
		{id: lbID, name: "web", public: true, selector: map[string]string{"app": "web"}},
		{id: clusterID, name: "internal", public: false, selector: map[string]string{"app": "internal"}},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	if edgeTo(batch.Edges, graph.InternetNodeID, privateID, graph.EdgeReachable) != nil {
		t.Fatal("a pod with app.kubernetes.io/name is not internet-reachable")
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) == nil {
		t.Fatal("LoadBalancer-selected pod should be reachable")
	}
	if edgeTo(batch.Edges, webID, lbID, graph.EdgeAffects) == nil {
		t.Fatal("LoadBalancer should be linked to the pod it selects")
	}
	if edgeTo(batch.Edges, privateID, lbID, graph.EdgeAffects) != nil {
		t.Fatal("LoadBalancer should not link to the unlabeled-for-it private pod")
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, internalID, graph.EdgeReachable) != nil {
		t.Fatal("ClusterIP-selected pod is not internet-reachable")
	}
	if edgeTo(batch.Edges, internalID, clusterID, graph.EdgeAffects) == nil {
		t.Fatal("ClusterIP should still be linked to the pod it selects")
	}
}

func TestServiceTypeExposure(t *testing.T) {
	if !serviceExposesInternet("LoadBalancer") {
		t.Fatal("LoadBalancer publishes selected pods")
	}
	if serviceExposesInternet("NodePort") {
		t.Fatal("NodePort alone does not publish selected pods")
	}
	if serviceExposesInternet("ClusterIP") {
		t.Fatal("ClusterIP does not publish selected pods")
	}
}

func TestIngressPublishesClusterIP(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")
	nodePortID := c.nodeID("workload", "apps/nodeport")
	webSvc := c.nodeID("network", "apps/service/web")
	nodeSvc := c.nodeID("network", "apps/service/nodeport")
	ingressID := c.nodeID("network", "apps/ingress/public")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
		{id: nodePortID, labels: map[string]string{"app": "nodeport"}},
	}, []collectedService{
		{id: webSvc, name: "web", public: false, selector: map[string]string{"app": "web"}},
		{id: nodeSvc, name: "nodeport", public: serviceExposesInternet("NodePort"), selector: map[string]string{"app": "nodeport"}},
	}, []*networkingv1.Ingress{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "public", Namespace: "apps"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					Host: "app.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{Name: "web"},
								},
							}, {
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{Name: "web"},
								},
							}},
						},
					},
				}},
			},
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	edge := edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable)
	if edge == nil {
		t.Fatal("Ingress backend should make the ClusterIP pod reachable")
	}
	if edge.Properties["via"] != "public" {
		t.Fatalf("via = %v, want ingress name", edge.Properties["via"])
	}
	if edgeTo(batch.Edges, webID, ingressID, graph.EdgeAffects) == nil {
		t.Fatal("pod should link to the Ingress that publishes it")
	}
	if nodeByName(batch.Nodes, "public") == nil {
		t.Fatal("Ingress should be recorded")
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, nodePortID, graph.EdgeReachable) != nil {
		t.Fatal("NodePort with no Ingress is not internet-reachable")
	}
}

func TestIngressDefaultBackendPublishesService(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", selector: map[string]string{"app": "web"}},
	}, []*networkingv1.Ingress{{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "apps"},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{Name: "web"},
			},
		},
	}}, nil); err != nil {
		t.Fatal(err)
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) == nil {
		t.Fatal("default backend should publish the selected pod")
	}
}

func TestNetworkPolicyBlocksLoadBalancer(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")
	otherID := c.nodeID("workload", "apps/other")

	var batch graph.Batch
	batch.Nodes = append(batch.Nodes,
		graph.Node{ID: webID, Type: graph.NodeWorkload, Name: "web", Properties: map[string]any{}},
		graph.Node{ID: otherID, Type: graph.NodeWorkload, Name: "other", Properties: map[string]any{}},
	)
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
		{id: otherID, labels: map[string]string{"app": "other"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", public: true, selector: map[string]string{"app": "web"}},
		{id: c.nodeID("network", "apps/service/other"), name: "other", public: true, selector: map[string]string{"app": "other"}},
	}, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-only", Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{},
				}},
			}},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) != nil {
		t.Fatal("NetworkPolicy that admits only pods should remove internet reachability")
	}
	if got := nodeByName(batch.Nodes, "web").Properties["network_policy"]; got != "cluster-only" {
		t.Fatalf("network_policy = %v, want cluster-only", got)
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, otherID, graph.EdgeReachable) == nil {
		t.Fatal("a pod the policy does not select stays reachable")
	}
	if nodeByName(batch.Nodes, "other").Properties["network_policy"] != nil {
		t.Fatal("unselected pod should not record a network policy")
	}
}

func TestNetworkPolicyAllowsWorld(t *testing.T) {
	c := NewCollector("demo", "apps")
	openID := c.nodeID("workload", "apps/open")
	v6ID := c.nodeID("workload", "apps/v6")
	exceptID := c.nodeID("workload", "apps/except")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: openID, labels: map[string]string{"app": "open"}},
		{id: v6ID, labels: map[string]string{"app": "v6"}},
		{id: exceptID, labels: map[string]string{"app": "except"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/open"), name: "open", public: true, selector: map[string]string{"app": "open"}},
		{id: c.nodeID("network", "apps/service/v6"), name: "v6", public: true, selector: map[string]string{"app": "v6"}},
		{id: c.nodeID("network", "apps/service/except"), name: "except", public: true, selector: map[string]string{"app": "except"}},
	}, nil, []*networkingv1.NetworkPolicy{
		policyWithIngress("allow-all", "open", networkingv1.NetworkPolicyIngressRule{}),
		policyWithIngress("allow-v6", "v6", networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "::/0"},
			}},
		}),
		policyWithIngress("allow-except", "except", networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{"203.0.113.0/24"}},
			}},
		}),
	}); err != nil {
		t.Fatal(err)
	}

	if edgeTo(batch.Edges, graph.InternetNodeID, openID, graph.EdgeReachable) == nil {
		t.Fatal("empty From should keep the LoadBalancer pod reachable")
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, v6ID, graph.EdgeReachable) == nil {
		t.Fatal("::/0 should keep the LoadBalancer pod reachable")
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, exceptID, graph.EdgeReachable) != nil {
		t.Fatal("0.0.0.0/0 with exceptions is not treated as world access")
	}
}

func TestAnyAllowingPolicyKeepsReachability(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")

	var batch graph.Batch
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID: webID, Type: graph.NodeWorkload, Name: "web", Properties: map[string]any{},
	})
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", public: true, selector: map[string]string{"app": "web"}},
	}, nil, []*networkingv1.NetworkPolicy{
		policyWithIngress("cluster-only", "web", networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{},
			}},
		}),
		policyWithIngress("world", "web", networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
		}),
	}); err != nil {
		t.Fatal(err)
	}

	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) == nil {
		t.Fatal("one world allow should keep the pod reachable")
	}
	if got := nodeByName(batch.Nodes, "web").Properties["network_policy"]; got != "cluster-only,world" {
		t.Fatalf("network_policy = %v, want cluster-only,world", got)
	}
}

func TestEgressOnlyPolicyDoesNotBlock(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")

	var batch graph.Batch
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID: webID, Type: graph.NodeWorkload, Name: "web", Properties: map[string]any{},
	})
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", public: true, selector: map[string]string{"app": "web"}},
	}, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) == nil {
		t.Fatal("an egress-only policy should not remove internet reachability")
	}
	if got := nodeByName(batch.Nodes, "web").Properties["network_policy"]; got != "egress" {
		t.Fatalf("network_policy = %v, want egress", got)
	}
}

func TestEmptyPolicySelectorBlocksNamespace(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", public: true, selector: map[string]string{"app": "web"}},
	}, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-ingress", Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) != nil {
		t.Fatal("an empty pod selector with no world rule should block the namespace")
	}
}

func TestPolicyMatchExpressionSelectsPod(t *testing.T) {
	c := NewCollector("demo", "apps")
	webID := c.nodeID("workload", "apps/web")

	var batch graph.Batch
	if err := c.linkExposure(&batch, []collectedPod{
		{id: webID, labels: map[string]string{"app": "web"}},
	}, []collectedService{
		{id: c.nodeID("network", "apps/service/web"), name: "web", public: true, selector: map[string]string{"app": "web"}},
	}, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "expr", Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"web"},
				}},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	if edgeTo(batch.Edges, graph.InternetNodeID, webID, graph.EdgeReachable) != nil {
		t.Fatal("matchExpressions should select the pod and block world ingress")
	}
}

func TestInvalidPolicySelector(t *testing.T) {
	c := NewCollector("demo", "apps")
	err := c.linkExposure(&graph.Batch{}, nil, nil, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: metav1.LabelSelectorOperator("Nope"),
				}},
			},
		},
	}})
	if err == nil {
		t.Fatal("invalid selector should fail the link")
	}
}

func policyWithIngress(name, app string, rule networkingv1.NetworkPolicyIngressRule) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{rule},
		},
	}
}

func edgeTo(edges []graph.Edge, source, target, edgeType string) *graph.Edge {
	for i := range edges {
		edge := &edges[i]
		if edge.SourceID == source && edge.TargetID == target && edge.Type == edgeType {
			return edge
		}
	}
	return nil
}

func nodeByName(nodes []graph.Node, name string) *graph.Node {
	for i := range nodes {
		if nodes[i].Name == name {
			return &nodes[i]
		}
	}
	return nil
}
