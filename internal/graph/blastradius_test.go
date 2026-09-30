// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestBlastRadiusFollowsAssumedRole(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		user = "identity:dev"
		role = "identity:admin"
		db   = "datastore:prod"
		net  = "network:public"
	)
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: user, Type: graph.NodeIdentity, Name: "dev"},
			{ID: role, Type: graph.NodeIdentity, Name: "AdminRole"},
			{ID: db, Type: graph.NodeDatastore, Name: "prod-db"},
			{ID: net, Type: graph.NodeNetwork, Name: "public"},
		},
		Edges: []graph.Edge{
			blastEdge(user, role, graph.EdgeAssumes),
			blastEdge(role, db, graph.EdgeCanAccess),
			blastEdge(user, net, graph.EdgeReachable),
		},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	result, err := store.BlastRadius(ctx, user, 6)
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	if result.Identity.ID != user || result.Identity.Name != "dev" {
		t.Fatalf("identity = %s %q", result.Identity.ID, result.Identity.Name)
	}
	if result.MaxDepth != 6 {
		t.Fatalf("MaxDepth = %d, want 6", result.MaxDepth)
	}
	got := blastIDs(result.Reachable)
	want := []string{db, role}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("reachable = %v, want datastore via the assumed role, not the network", got)
	}
	wantSummary := "Identity dev can reach 2 resources (0 workloads, 1 datastores, 0 networks)"
	if result.Summary != wantSummary {
		t.Fatalf("summary = %q, want %q", result.Summary, wantSummary)
	}
}

func TestBlastRadiusStopsAtMaxDepth(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		walker = "identity:walker"
		hopA   = "workload:a"
		hopB   = "workload:b"
		hopC   = "datastore:c"
		net    = "network:ignored"
	)
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: walker, Type: graph.NodeIdentity, Name: "walker"},
			{ID: hopA, Type: graph.NodeWorkload, Name: "a"},
			{ID: hopB, Type: graph.NodeWorkload, Name: "b"},
			{ID: hopC, Type: graph.NodeDatastore, Name: "c"},
			{ID: net, Type: graph.NodeNetwork, Name: "ignored"},
		},
		Edges: []graph.Edge{
			blastEdge(walker, hopA, graph.EdgeCanAccess),
			blastEdge(hopA, hopB, graph.EdgeCanAccess),
			blastEdge(hopB, hopC, graph.EdgeCanAccess),
			blastEdge(walker, net, graph.EdgeReachable),
		},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	shallow, err := store.BlastRadius(ctx, walker, 2)
	if err != nil {
		t.Fatalf("BlastRadius depth 2: %v", err)
	}
	if shallow.MaxDepth != 2 {
		t.Fatalf("MaxDepth = %d, want 2", shallow.MaxDepth)
	}
	if got := strings.Join(blastIDs(shallow.Reachable), ","); got != hopA+","+hopB {
		t.Fatalf("depth 2 reachable = %s, want %s and %s", got, hopA, hopB)
	}

	full, err := store.BlastRadius(ctx, walker, 0)
	if err != nil {
		t.Fatalf("BlastRadius default depth: %v", err)
	}
	if full.MaxDepth != 6 {
		t.Fatalf("default MaxDepth = %d, want 6", full.MaxDepth)
	}
	if got := strings.Join(blastIDs(full.Reachable), ","); got != hopC+","+hopA+","+hopB {
		t.Fatalf("default reachable = %s, want the chain and not the network", got)
	}
}

func blastEdge(source, target, edgeType string) graph.Edge {
	return graph.Edge{
		ID:       source + "|" + target + "|" + edgeType,
		SourceID: source,
		TargetID: target,
		Type:     edgeType,
	}
}

func blastIDs(nodes []graph.Node) []string {
	ids := make([]string, len(nodes))
	for i, node := range nodes {
		ids[i] = node.ID
	}
	return ids
}
