// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestReplaceInventoryDropsAbsentNodes(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		account = "111122223333"
		other   = "999988887777"
		kept    = "aws:111122223333:us-east-1:workload:kept"
		dropped = "aws:111122223333:us-east-1:workload:dropped"
		bucket  = "aws:111122223333:global:datastore:logs"
		role    = "aws:111122223333:global:identity:old-role"
		west    = "aws:111122223333:us-west-2:workload:west"
		foreign = "aws:999988887777:us-east-1:workload:other"
	)

	first := graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: kept, Type: graph.NodeWorkload, Name: "kept", Provider: "aws", Region: "us-east-1", AccountID: account},
			{ID: dropped, Type: graph.NodeWorkload, Name: "dropped", Provider: "aws", Region: "us-east-1", AccountID: account},
			{ID: bucket, Type: graph.NodeDatastore, Name: "logs", Provider: "aws", AccountID: account},
			{ID: role, Type: graph.NodeIdentity, Name: "old-role", Provider: "aws", AccountID: account},
			{ID: west, Type: graph.NodeWorkload, Name: "west", Provider: "aws", Region: "us-west-2", AccountID: account},
			{ID: foreign, Type: graph.NodeWorkload, Name: "other", Provider: "aws", Region: "us-east-1", AccountID: other},
			findingNode("cve-kept", kept, account, "cve"),
			findingNode("cve-dropped", dropped, account, "cve"),
		},
		Edges: []graph.Edge{
			reach(graph.InternetNodeID, kept),
			reach(graph.InternetNodeID, dropped),
			reach(graph.InternetNodeID, west),
			reach(graph.InternetNodeID, foreign),
			access(kept, bucket),
			violates("cve-kept", kept),
			violates("cve-dropped", dropped),
		},
	}
	if err := store.UpsertBatch(ctx, first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	second := graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: kept, Type: graph.NodeWorkload, Name: "kept", Provider: "aws", Region: "us-east-1", AccountID: account},
			{ID: bucket, Type: graph.NodeDatastore, Name: "logs", Provider: "aws", AccountID: account},
		},
		Edges: []graph.Edge{
			reach(graph.InternetNodeID, kept),
		},
	}
	err := store.ReplaceInventory(ctx, []graph.Scope{{
		AccountID: account,
		Regions:   []string{"us-east-1", ""},
	}}, second)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}

	requireNode(t, ctx, store, dropped, false)
	requireNode(t, ctx, store, role, false)
	requireNode(t, ctx, store, "finding:cve-dropped:"+dropped, false)
	requireNode(t, ctx, store, kept, true)
	requireNode(t, ctx, store, bucket, true)
	requireNode(t, ctx, store, west, true)
	requireNode(t, ctx, store, foreign, true)
	requireNode(t, ctx, store, graph.InternetNodeID, true)
	requireNode(t, ctx, store, "finding:cve-kept:"+kept, true)

	requireEdge(t, ctx, store, graph.InternetNodeID, kept, graph.EdgeReachable, true)
	requireEdge(t, ctx, store, graph.InternetNodeID, dropped, graph.EdgeReachable, false)
	requireEdge(t, ctx, store, kept, bucket, graph.EdgeCanAccess, false)
	requireEdge(t, ctx, store, graph.InternetNodeID, west, graph.EdgeReachable, true)
	requireEdge(t, ctx, store, graph.InternetNodeID, foreign, graph.EdgeReachable, true)
	requireEdge(t, ctx, store, "finding:cve-kept:"+kept, kept, graph.EdgeViolates, true)
}

func TestReplaceInventoryKeepsOtherNamespaces(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		cluster = "cluster-demo"
		prod    = "k8s:cluster-demo:workload:prod/api"
		dev     = "k8s:cluster-demo:workload:dev/api"
	)
	seed := graph.Batch{
		Nodes: []graph.Node{
			{ID: prod, Type: graph.NodeWorkload, Name: "api", Provider: "kubernetes", AccountID: cluster, Properties: map[string]any{"namespace": "prod"}},
			{ID: dev, Type: graph.NodeWorkload, Name: "api", Provider: "kubernetes", AccountID: cluster, Properties: map[string]any{"namespace": "dev"}},
		},
	}
	if err := store.UpsertBatch(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := store.ReplaceInventory(ctx, []graph.Scope{{
		AccountID: cluster,
		Namespace: "prod",
	}}, graph.Batch{})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}

	requireNode(t, ctx, store, prod, false)
	requireNode(t, ctx, store, dev, true)
}

func findingNode(id, resource, account, findingType string) graph.Node {
	return graph.Node{
		ID:        "finding:" + id + ":" + resource,
		Type:      graph.NodeFinding,
		Name:      id,
		Provider:  "aws",
		AccountID: account,
		Properties: map[string]any{
			"finding_type":      findingType,
			"affected_resource": resource,
		},
	}
}

func reach(source, target string) graph.Edge {
	return graph.Edge{
		ID:       source + "|" + target + "|" + graph.EdgeReachable,
		SourceID: source,
		TargetID: target,
		Type:     graph.EdgeReachable,
	}
}

func access(source, target string) graph.Edge {
	return graph.Edge{
		ID:       source + "|" + target + "|" + graph.EdgeCanAccess,
		SourceID: source,
		TargetID: target,
		Type:     graph.EdgeCanAccess,
	}
}

func violates(id, resource string) graph.Edge {
	findingID := "finding:" + id + ":" + resource
	return graph.Edge{
		ID:       findingID + "|" + resource + "|" + graph.EdgeViolates,
		SourceID: findingID,
		TargetID: resource,
		Type:     graph.EdgeViolates,
	}
}

func requireNode(t *testing.T, ctx context.Context, store *graph.Store, id string, want bool) {
	t.Helper()
	var exists bool
	if err := store.Pool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1)`, id).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("node %s exists=%v, want %v", id, exists, want)
	}
}

func requireEdge(t *testing.T, ctx context.Context, store *graph.Store, source, target, edgeType string, want bool) {
	t.Helper()
	var exists bool
	err := store.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM edges
			WHERE source_id = $1 AND target_id = $2 AND type = $3
		)
	`, source, target, edgeType).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("edge %s -> %s (%s) exists=%v, want %v", source, target, edgeType, exists, want)
	}
}
