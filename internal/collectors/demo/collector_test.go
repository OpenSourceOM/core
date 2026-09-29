// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package demo

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestCollectSampleEnvironment(t *testing.T) {
	batch := Collect()
	if len(batch.Nodes) < 10 {
		t.Fatalf("nodes = %d, want at least 10", len(batch.Nodes))
	}
	if len(batch.Edges) < 8 {
		t.Fatalf("edges = %d, want at least 8", len(batch.Edges))
	}

	ids := map[string]graph.Node{}
	for _, n := range batch.Nodes {
		ids[n.ID] = n
	}
	for _, id := range []string{
		graph.InternetNodeID,
		WebInstanceID,
		ProdDBID,
		PublicLogsID,
		AdminRoleID,
		K8sFrontendID,
	} {
		if _, ok := ids[id]; !ok {
			t.Errorf("missing node %s", id)
		}
	}

	public := ids[PublicLogsID]
	if v, _ := public.Properties["public_access"].(bool); !v {
		t.Fatal("expected public bucket to have public_access")
	}
	db := ids[ProdDBID]
	if v, _ := db.Properties["public_access"].(bool); v {
		t.Fatal("prod-db is private")
	}
	admin := ids[AdminRoleID]
	if v, _ := admin.Properties["admin_access"].(bool); !v {
		t.Fatal("AdminRole has administrator access")
	}
	webPkgs, _ := ids[WebInstanceID].Properties["packages"].([]any)
	workerPkgs, _ := ids[WorkerInstanceID].Properties["packages"].([]any)
	if len(webPkgs) != 1 || webPkgs[0] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Fatalf("web-1 packages = %#v", webPkgs)
	}
	if len(workerPkgs) != 1 || workerPkgs[0] != "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*" {
		t.Fatalf("worker-1 packages = %#v", workerPkgs)
	}
	if ids[K8sFrontendID].Properties["image"] != "nginx:1.25.3" {
		t.Fatalf("frontend image = %#v", ids[K8sFrontendID].Properties["image"])
	}
	if _, ok := admin.Properties["mfa"]; ok {
		t.Fatal("AdminRole is an instance role and has no MFA property")
	}
}

func TestAttackPathIsCheckable(t *testing.T) {
	batch := Collect()
	hops, err := AttackHops(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 4 {
		t.Fatalf("hops = %d, want 4", len(hops))
	}
	if hops[0].Type != graph.EdgeReachable || hops[0].TargetName != "sg-web" {
		t.Fatalf("first hop = %+v", hops[0])
	}
	if hops[1].TargetName != "web-1" {
		t.Fatalf("second hop target = %s", hops[1].TargetName)
	}
	if hops[2].Type != graph.EdgeAssumes || hops[2].TargetName != "AdminRole" {
		t.Fatalf("third hop = %+v, want web-1 ASSUMES AdminRole", hops[2])
	}
	if hops[3].Type != graph.EdgeCanAccess || hops[3].TargetName != "prod-db" {
		t.Fatalf("fourth hop = %+v, want AdminRole CAN_ACCESS prod-db", hops[3])
	}

	for _, edge := range batch.Edges {
		if edge.SourceID == AdminRoleID && edge.TargetID == WebInstanceID {
			t.Fatal("AdminRole must not point at web-1; the instance assumes the role")
		}
		if edge.SourceID == WebInstanceID && edge.TargetID == ProdDBID {
			t.Fatal("web-1 must not link directly to prod-db")
		}
	}
}

func TestPrivateWorkerIsNotInternetReachable(t *testing.T) {
	batch := Collect()
	seen := map[string]bool{graph.InternetNodeID: true}
	var queue []string
	queue = append(queue, graph.InternetNodeID)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range batch.Edges {
			if edge.Type != graph.EdgeReachable || edge.SourceID != current || seen[edge.TargetID] {
				continue
			}
			seen[edge.TargetID] = true
			queue = append(queue, edge.TargetID)
		}
	}
	if seen[WorkerInstanceID] {
		t.Fatal("worker-1 is reachable from the internet")
	}
	if seen[PrivateAssetsID] {
		t.Fatal("acme-assets is reachable from the internet")
	}
	if !seen[WebInstanceID] {
		t.Fatal("web-1 should be reachable from the internet through sg-web")
	}
	if seen[ProdDBID] {
		t.Fatal("prod-db is private and must not be REACHABLE from the internet")
	}
	if !seen[K8sFrontendID] || !seen[PublicLogsID] {
		t.Fatal("frontend and the public logs bucket are reachable from the internet")
	}
}
