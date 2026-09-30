// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestAttackPathCombinationUsesShortestHop(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const (
		sg   = "aws:111122223333:us-east-1:network:sg-web"
		web  = "aws:111122223333:us-east-1:workload:web"
		role = "aws:111122223333:us-east-1:identity:admin"
		db   = "aws:111122223333:us-east-1:datastore:prod"
		cve  = "finding:cve-2021-44228:" + web
	)
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + typ, SourceID: src, TargetID: dst, Type: typ}
	}
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: sg, Type: graph.NodeNetwork, Name: "sg-web", Provider: "aws"},
			{ID: web, Type: graph.NodeWorkload, Name: "web-1", Provider: "aws"},
			{ID: role, Type: graph.NodeIdentity, Name: "AdminRole", Provider: "aws"},
			{ID: db, Type: graph.NodeDatastore, Name: "prod-db", Provider: "aws"},
			{
				ID: cve, Type: graph.NodeFinding, Name: "CVE-2021-44228", Provider: "aws",
				Properties: map[string]any{
					"finding_type":     "cve",
					"title":            "CVE-2021-44228",
					"normalized_score": 100,
				},
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, sg, graph.EdgeReachable),
			edge(sg, web, graph.EdgeReachable),
			edge(web, role, graph.EdgeAssumes),
			edge(role, db, graph.EdgeCanAccess),
			edge(web, db, graph.EdgeCanAccess),
			edge(cve, web, graph.EdgeViolates),
		},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	combos, err := store.ListAttackPathCombinations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(combos) != 1 {
		t.Fatalf("combinations = %d, want the direct hop", len(combos))
	}
	want := []string{graph.InternetNodeID, sg, web, db}
	if strings.Join(combos[0].Path, ",") != strings.Join(want, ",") {
		t.Fatalf("path = %v, want %v", combos[0].Path, want)
	}
	if combos[0].Finding.ID != cve || combos[0].Datastore.ID != db {
		t.Fatalf("combo = finding %s datastore %s", combos[0].Finding.ID, combos[0].Datastore.ID)
	}
}

func TestAttackPathCombinationViaAssumedIdentity(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)
	if err := store.UpsertBatch(ctx, attackPathIdentityBatch()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	combos, err := store.ListAttackPathCombinations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(combos) != 1 {
		t.Fatalf("combinations = %d, want 1", len(combos))
	}
	want := []string{graph.InternetNodeID, attackPathSG, attackPathWeb, attackPathRole, attackPathDB}
	if strings.Join(combos[0].Path, ",") != strings.Join(want, ",") {
		t.Fatalf("path = %v, want %v", combos[0].Path, want)
	}
}

func TestAttackPathCombinationRequiresFindingOnReachableWorkload(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	batch := attackPathIdentityBatch()
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID: attackPathPrivate, Type: graph.NodeWorkload, Name: "worker-1", Provider: "aws",
	}, graph.Node{
		ID: attackPathAppRole, Type: graph.NodeIdentity, Name: "AppRole", Provider: "aws",
	}, graph.Node{
		ID: attackPathPrivateDB, Type: graph.NodeDatastore, Name: "assets", Provider: "aws",
	}, graph.Node{
		ID: attackPathPrivateFinding, Type: graph.NodeFinding, Name: "CVE-2021-44228", Provider: "aws",
		Properties: map[string]any{"finding_type": "cve", "normalized_score": 90},
	}, graph.Node{
		ID: attackPathNetworkFinding, Type: graph.NodeFinding, Name: "Open security group", Provider: "aws",
		Properties: map[string]any{"finding_type": "cspm", "normalized_score": 70},
	})
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + typ, SourceID: src, TargetID: dst, Type: typ}
	}
	batch.Edges = append(batch.Edges,
		edge(attackPathPrivate, attackPathAppRole, graph.EdgeAssumes),
		edge(attackPathAppRole, attackPathPrivateDB, graph.EdgeCanAccess),
		edge(attackPathPrivateFinding, attackPathPrivate, graph.EdgeViolates),
		edge(attackPathNetworkFinding, attackPathSG, graph.EdgeViolates),
	)
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	combos, err := store.ListAttackPathCombinations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(combos) != 1 || combos[0].Workload.ID != attackPathWeb {
		t.Fatalf("combinations = %+v, want only the reachable workload", combos)
	}

	if _, err := store.Pool().Exec(ctx, `DELETE FROM nodes WHERE id = $1`, attackPathCVE); err != nil {
		t.Fatal(err)
	}
	combos, err = store.ListAttackPathCombinations(ctx)
	if err != nil {
		t.Fatalf("list without finding: %v", err)
	}
	if len(combos) != 0 {
		t.Fatalf("combinations = %d, want none without a finding on the workload", len(combos))
	}
}

func TestAttackPathCombinationIgnoresAttackPathFindings(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)
	batch := attackPathIdentityBatch()
	batch.Nodes[len(batch.Nodes)-1].Properties = map[string]any{
		"finding_type": graph.FindingTypeAttackPath,
		"rule_id":      "attack-path",
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}
	combos, err := store.ListAttackPathCombinations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(combos) != 0 {
		t.Fatalf("combinations = %d, want none from an attack-path finding", len(combos))
	}
}

const (
	attackPathSG             = "aws:111122223333:us-east-1:network:sg-web"
	attackPathWeb            = "aws:111122223333:us-east-1:workload:web"
	attackPathRole           = "aws:111122223333:us-east-1:identity:admin"
	attackPathDB             = "aws:111122223333:us-east-1:datastore:prod"
	attackPathCVE            = "finding:cve-2021-44228:" + attackPathWeb
	attackPathPrivate        = "aws:111122223333:us-east-1:workload:worker"
	attackPathAppRole        = "aws:111122223333:us-east-1:identity:app"
	attackPathPrivateDB      = "aws:111122223333:us-east-1:datastore:assets"
	attackPathPrivateFinding = "finding:cve-2021-44228:" + attackPathPrivate
	attackPathNetworkFinding = "finding:cspm-sg:" + attackPathSG
)

func attackPathIdentityBatch() graph.Batch {
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + typ, SourceID: src, TargetID: dst, Type: typ}
	}
	return graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: attackPathSG, Type: graph.NodeNetwork, Name: "sg-web", Provider: "aws"},
			{ID: attackPathWeb, Type: graph.NodeWorkload, Name: "web-1", Provider: "aws"},
			{ID: attackPathRole, Type: graph.NodeIdentity, Name: "AdminRole", Provider: "aws"},
			{ID: attackPathDB, Type: graph.NodeDatastore, Name: "prod-db", Provider: "aws"},
			{
				ID: attackPathCVE, Type: graph.NodeFinding, Name: "CVE-2021-44228", Provider: "aws",
				Properties: map[string]any{
					"finding_type":     "cve",
					"title":            "CVE-2021-44228",
					"normalized_score": 100,
				},
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, attackPathSG, graph.EdgeReachable),
			edge(attackPathSG, attackPathWeb, graph.EdgeReachable),
			edge(attackPathWeb, attackPathRole, graph.EdgeAssumes),
			edge(attackPathRole, attackPathDB, graph.EdgeCanAccess),
			edge(attackPathCVE, attackPathWeb, graph.EdgeViolates),
		},
	}
}
