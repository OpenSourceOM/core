// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/collectors/demo"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/rules"
)

func TestAttackPathFindingRecordsPathAndSkipsIncompleteGraphs(t *testing.T) {
	ctx := context.Background()
	store := openRulesFixture(t)

	const (
		web = "aws:111122223333:us-east-1:workload:web"
		db  = "aws:111122223333:us-east-1:datastore:prod"
		sg  = "aws:111122223333:us-east-1:network:sg-web"
		cve = "finding:cve-2021-44228:" + web
	)
	if err := store.UpsertBatch(ctx, attackPathBatch(web, db, sg, cve)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	none, err := rules.NewEngine(store).Run(ctx, "attack-path")
	if err != nil {
		t.Fatalf("run without hop: %v", err)
	}
	if none.FindingsCreated != 0 {
		t.Fatalf("FindingsCreated = %d, want 0 before the datastore hop exists", none.FindingsCreated)
	}

	hop := graph.Edge{
		ID: web + "|" + db + "|" + graph.EdgeCanAccess, SourceID: web, TargetID: db, Type: graph.EdgeCanAccess,
	}
	if err := store.UpsertBatch(ctx, graph.Batch{Edges: []graph.Edge{hop}}); err != nil {
		t.Fatalf("add hop: %v", err)
	}

	result, err := rules.NewEngine(store).Run(ctx, "attack-path")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.FindingsCreated != 1 {
		t.Fatalf("FindingsCreated = %d, want 1", result.FindingsCreated)
	}
	if len(result.Matches) != 1 || len(result.Matches[0].Path) == 0 {
		t.Fatalf("match path = %#v", result.Matches)
	}

	findingID := "finding:attack-path:" + cve + ":" + db
	node, err := store.GetNode(ctx, findingID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if node.Properties["finding_type"] != graph.FindingTypeAttackPath {
		t.Fatalf("finding_type = %#v", node.Properties["finding_type"])
	}
	if node.Properties["source_finding_id"] != cve || node.Properties["datastore_id"] != db {
		t.Fatalf("properties = %#v", node.Properties)
	}
	wantPath := []string{graph.InternetNodeID, sg, web, db}
	page, err := store.ListFindings(ctx, 20, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var viewed graph.FindingView
	for _, view := range page.Findings {
		if view.Finding.ID == findingID {
			viewed = view
			break
		}
	}
	if viewed.Finding.ID == "" {
		t.Fatal("findings list omitted the attack-path row")
	}
	if strings.Join(viewed.Path, ",") != strings.Join(wantPath, ",") {
		t.Fatalf("list path = %v, want %v", viewed.Path, wantPath)
	}
	if viewed.AffectedResourceID != web {
		t.Fatalf("affected resource = %s, want the workload", viewed.AffectedResourceID)
	}
	if viewed.Finding.Properties["severity"] != "critical" {
		t.Fatalf("severity = %#v, want the source score band", viewed.Finding.Properties["severity"])
	}

	if _, err := store.Pool().Exec(ctx, `DELETE FROM edges WHERE id = $1`, hop.ID); err != nil {
		t.Fatal(err)
	}
	again, err := rules.NewEngine(store).Run(ctx, "attack-path")
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if again.FindingsCreated != 0 {
		t.Fatalf("FindingsCreated = %d, want 0 after the hop is removed", again.FindingsCreated)
	}
	requireRuleNode(t, ctx, store, findingID, false)
	requireRuleNode(t, ctx, store, cve, true)
}

func TestRunAllWritesAttackPathWithoutDroppingControlFindings(t *testing.T) {
	ctx := context.Background()
	store := openRulesFixture(t)

	const (
		web    = "aws:111122223333:us-east-1:workload:web"
		db     = "aws:111122223333:us-east-1:datastore:prod"
		public = "aws:111122223333:global:datastore:public-logs"
		sg     = "aws:111122223333:us-east-1:network:sg-web"
	)
	batch := attackPathBatch(web, db, sg, "")
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID: public, Type: graph.NodeDatastore, Name: "public-logs", Provider: "aws", AccountID: "111122223333",
		Properties: map[string]any{"public_access": true},
	})
	batch.Edges = append(batch.Edges, graph.Edge{
		ID: web + "|" + db + "|" + graph.EdgeCanAccess, SourceID: web, TargetID: db, Type: graph.EdgeCanAccess,
	})
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	result, err := rules.NewEngine(store).RunAll(ctx)
	if err != nil {
		t.Fatalf("run all: %v", err)
	}
	if result.FindingsCreated < 2 {
		t.Fatalf("FindingsCreated = %d, want the control finding and the attack path", result.FindingsCreated)
	}
	requireRuleNode(t, ctx, store, "finding:cspm-public-datastore:"+public, true)

	internetFinding := "finding:cspm-internet-workload:" + web
	requireRuleNode(t, ctx, store, internetFinding, true)
	attackID := "finding:attack-path:" + internetFinding + ":" + db
	requireRuleNode(t, ctx, store, attackID, true)

	again, err := rules.NewEngine(store).RunAll(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again.FindingsCreated < 2 {
		t.Fatalf("second FindingsCreated = %d", again.FindingsCreated)
	}
	var attackPaths int
	err = store.Pool().QueryRow(ctx, `
		SELECT COUNT(*) FROM nodes
		WHERE type = $1 AND properties->>'finding_type' = $2
	`, graph.NodeFinding, graph.FindingTypeAttackPath).Scan(&attackPaths)
	if err != nil {
		t.Fatal(err)
	}
	if attackPaths != 1 {
		t.Fatalf("attack-path findings = %d, want 1 after a second run", attackPaths)
	}
}

func TestDemoGraphWritesAttackPathThroughAdminRole(t *testing.T) {
	ctx := context.Background()
	store := openRulesFixture(t)
	if err := store.UpsertBatch(ctx, demo.Collect()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := rules.NewEngine(store).RunAll(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	page, err := store.ListFindings(ctx, 200, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{
		graph.InternetNodeID,
		demo.SecurityGroupWebID,
		demo.WebInstanceID,
		demo.AdminRoleID,
		demo.ProdDBID,
	}
	var paths int
	for _, view := range page.Findings {
		if view.Finding.Properties["finding_type"] != graph.FindingTypeAttackPath {
			continue
		}
		paths++
		if strings.Join(view.Path, ",") != strings.Join(want, ",") {
			t.Fatalf("path = %v, want %v", view.Path, want)
		}
		if view.AffectedResourceID != demo.WebInstanceID {
			t.Fatalf("affected = %s", view.AffectedResourceID)
		}
		if view.Finding.Properties["datastore_id"] != demo.ProdDBID {
			t.Fatalf("datastore = %#v", view.Finding.Properties["datastore_id"])
		}
	}
	if paths != 3 {
		t.Fatalf("attack-path findings = %d, want one per finding on web-1", paths)
	}
}

func attackPathBatch(web, db, sg, findingID string) graph.Batch {
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + typ, SourceID: src, TargetID: dst, Type: typ}
	}
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: sg, Type: graph.NodeNetwork, Name: "sg-web", Provider: "aws", AccountID: "111122223333"},
			{ID: web, Type: graph.NodeWorkload, Name: "web-1", Provider: "aws", Region: "us-east-1", AccountID: "111122223333"},
			{ID: db, Type: graph.NodeDatastore, Name: "prod-db", Provider: "aws", AccountID: "111122223333"},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, sg, graph.EdgeReachable),
			edge(sg, web, graph.EdgeReachable),
		},
	}
	if findingID != "" {
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID: findingID, Type: graph.NodeFinding, Name: "CVE-2021-44228", Provider: "aws", AccountID: "111122223333",
			Properties: map[string]any{
				"finding_type":      "cve",
				"title":             "CVE-2021-44228",
				"normalized_score":  100,
				"affected_resource": web,
			},
		})
		batch.Edges = append(batch.Edges, edge(findingID, web, graph.EdgeViolates))
	}
	return batch
}
