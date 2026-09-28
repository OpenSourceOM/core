// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestServiceExposureSelectsPods(t *testing.T) {
	c := NewCollector("demo", "apps")
	privateID := c.nodeID("workload", "apps/private")
	webID := c.nodeID("workload", "apps/web")
	internalID := c.nodeID("workload", "apps/internal")
	lbID := c.nodeID("network", "apps/service/web")
	clusterID := c.nodeID("network", "apps/service/internal")

	var batch graph.Batch
	c.linkServicesToPods(&batch, []collectedPod{
		{id: privateID, labels: map[string]string{"app.kubernetes.io/name": "private"}},
		{id: webID, labels: map[string]string{"app": "web"}},
		{id: internalID, labels: map[string]string{"app": "internal"}},
	}, []collectedService{
		{id: lbID, name: "web", public: true, selector: map[string]string{"app": "web"}},
		{id: clusterID, name: "internal", public: false, selector: map[string]string{"app": "internal"}},
	})

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

func edgeTo(edges []graph.Edge, source, target, edgeType string) *graph.Edge {
	for i := range edges {
		edge := &edges[i]
		if edge.SourceID == source && edge.TargetID == target && edge.Type == edgeType {
			return edge
		}
	}
	return nil
}
