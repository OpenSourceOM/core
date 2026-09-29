// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestListNodesPagesPastTheFirstPage(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const page = 2
	var nodes []graph.Node
	for i := 0; i < page+1; i++ {
		nodes = append(nodes, graph.Node{
			ID:       fmt.Sprintf("aws:111:us-east-1:workload:n-%d", i),
			Type:     graph.NodeWorkload,
			Name:     fmt.Sprintf("n-%d", i),
			Provider: "aws",
		})
	}
	nodes = append(nodes, graph.Node{
		ID: "aws:111:global:datastore:bucket", Type: graph.NodeDatastore, Name: "bucket", Provider: "aws",
	})
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	first, err := store.ListNodes(ctx, graph.NodeWorkload, page, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Nodes) != page || first.NextCursor == "" {
		t.Fatalf("first page = %d nodes cursor %q, want %d and a cursor", len(first.Nodes), first.NextCursor, page)
	}
	if first.Nodes[0].Name != "n-0" || first.Nodes[1].Name != "n-1" {
		t.Fatalf("first page names = %s, %s", first.Nodes[0].Name, first.Nodes[1].Name)
	}

	second, err := store.ListNodes(ctx, graph.NodeWorkload, page, first.NextCursor)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Nodes) != 1 || second.Nodes[0].Name != "n-2" || second.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}

	if _, err := store.ListNodes(ctx, graph.NodeDatastore, page, first.NextCursor); !errors.Is(err, graph.ErrInvalidCursor) {
		t.Fatalf("reused cursor err = %v, want invalid cursor", err)
	}
	if _, err := store.ListEdges(ctx, page, first.NextCursor); !errors.Is(err, graph.ErrInvalidCursor) {
		t.Fatalf("edge cursor err = %v, want invalid cursor", err)
	}
	if _, err := store.ListNodes(ctx, graph.NodeWorkload, page, "!!!"); !errors.Is(err, graph.ErrInvalidCursor) {
		t.Fatalf("bad cursor err = %v, want invalid cursor", err)
	}
}

func TestListNodesClampsToTheMaxPage(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	nodes := make([]graph.Node, 0, graph.MaxNodePageSize+1)
	for i := 0; i < graph.MaxNodePageSize+1; i++ {
		nodes = append(nodes, graph.Node{
			ID:       fmt.Sprintf("aws:111:us-east-1:workload:p-%04d", i),
			Type:     graph.NodeWorkload,
			Name:     fmt.Sprintf("p-%04d", i),
			Provider: "aws",
		})
	}
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	page, err := store.ListNodes(ctx, graph.NodeWorkload, graph.MaxNodePageSize+50, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Nodes) != graph.MaxNodePageSize || page.NextCursor == "" {
		t.Fatalf("page = %d nodes cursor %q, want %d and a cursor", len(page.Nodes), page.NextCursor, graph.MaxNodePageSize)
	}
	rest, err := store.ListNodes(ctx, graph.NodeWorkload, graph.MaxNodePageSize, page.NextCursor)
	if err != nil {
		t.Fatalf("rest: %v", err)
	}
	if len(rest.Nodes) != 1 || rest.NextCursor != "" {
		t.Fatalf("rest = %d nodes cursor %q", len(rest.Nodes), rest.NextCursor)
	}
}

func TestForEachNodeVisitsEveryNode(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	var nodes []graph.Node
	for i := 0; i < graph.MaxNodePageSize+1; i++ {
		nodes = append(nodes, graph.Node{
			ID:       fmt.Sprintf("aws:111:us-east-1:workload:e-%04d", i),
			Type:     graph.NodeWorkload,
			Name:     fmt.Sprintf("e-%04d", i),
			Provider: "aws",
		})
	}
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var seen int
	err := store.ForEachNode(ctx, graph.NodeWorkload, func(graph.Node) error {
		seen++
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachNode: %v", err)
	}
	if seen != graph.MaxNodePageSize+1 {
		t.Fatalf("visited %d, want %d", seen, graph.MaxNodePageSize+1)
	}
}

func TestListFindingsPagesByScore(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	batch := graph.Batch{Nodes: []graph.Node{
		findingWithScore("low", "low", 10),
		findingWithScore("high", "high", 30),
		findingWithScore("mid", "mid", 20),
		{
			ID:   "finding:unscored",
			Type: graph.NodeFinding,
			Name: "unscored",
			Properties: map[string]any{
				"finding_type": "cve",
			},
		},
	}}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	first, err := store.ListFindings(ctx, 2, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Findings) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d cursor %q", len(first.Findings), first.NextCursor)
	}
	if first.Findings[0].Finding.Name != "high" || first.Findings[1].Finding.Name != "mid" {
		t.Fatalf("order = %s, %s", first.Findings[0].Finding.Name, first.Findings[1].Finding.Name)
	}

	second, err := store.ListFindings(ctx, 2, first.NextCursor)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Findings) != 2 || second.NextCursor != "" {
		t.Fatalf("second page len = %d cursor %q", len(second.Findings), second.NextCursor)
	}
	if second.Findings[0].Finding.Name != "low" || second.Findings[1].Finding.Name != "unscored" {
		t.Fatalf("second page = %s, %s", second.Findings[0].Finding.Name, second.Findings[1].Finding.Name)
	}
}

func TestListEdgesPages(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		a = "aws:111:us-east-1:workload:a"
		b = "aws:111:us-east-1:workload:b"
		c = "aws:111:us-east-1:workload:c"
	)
	edge := func(src, dst string) graph.Edge {
		return graph.Edge{
			ID: src + "|" + dst + "|" + graph.EdgeReachable, SourceID: src, TargetID: dst, Type: graph.EdgeReachable,
		}
	}
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: a, Type: graph.NodeWorkload, Name: "a", Provider: "aws"},
			{ID: b, Type: graph.NodeWorkload, Name: "b", Provider: "aws"},
			{ID: c, Type: graph.NodeWorkload, Name: "c", Provider: "aws"},
		},
		Edges: []graph.Edge{edge(a, b), edge(b, c), edge(a, c)},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	first, err := store.ListEdges(ctx, 2, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Edges) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d cursor %q", len(first.Edges), first.NextCursor)
	}
	second, err := store.ListEdges(ctx, 2, first.NextCursor)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Edges) != 1 || second.NextCursor != "" {
		t.Fatalf("second page = %d cursor %q", len(second.Edges), second.NextCursor)
	}
}

func findingWithScore(id, name string, score int) graph.Node {
	return graph.Node{
		ID:   "finding:" + id,
		Type: graph.NodeFinding,
		Name: name,
		Properties: map[string]any{
			"normalized_score": score,
			"finding_type":     "cve",
		},
	}
}
