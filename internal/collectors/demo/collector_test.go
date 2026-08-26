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
		"aws:ec2:i-web-1",
		"aws:rds:prod-db",
		"aws:s3:acme-logs-public",
		"aws:iam:role/AdminRole",
		"k8s:svc:prod/frontend",
	} {
		if _, ok := ids[id]; !ok {
			t.Errorf("missing node %s", id)
		}
	}

	public := ids["aws:s3:acme-logs-public"]
	if v, _ := public.Properties["public_access"].(bool); !v {
		t.Fatal("expected public bucket to have public_access")
	}
}
