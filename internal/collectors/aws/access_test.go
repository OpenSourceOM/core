// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestLinkRoleS3Access(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	webID := c.nodeID("workload", "i-web")
	logsID := c.nodeID("datastore", "logs")
	privateID := c.nodeID("datastore", "private")
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: webID, Type: graph.NodeWorkload, Name: "web-1"},
			{
				ID: logsID, Type: graph.NodeDatastore, Name: "logs",
				Properties: map[string]any{"service": "s3"},
			},
			{
				ID: privateID, Type: graph.NodeDatastore, Name: "private",
				Properties: map[string]any{"service": "s3"},
			},
		},
	}

	c.ensureRoleNode(&batch, "AppRole", "arn:aws:iam::111122223333:role/AppRole")
	addEdge(&batch, graph.Edge{
		ID:       c.edgeID(webID, c.nodeID("identity", "AppRole"), graph.EdgeAssumes),
		SourceID: webID,
		TargetID: c.nodeID("identity", "AppRole"),
		Type:     graph.EdgeAssumes,
		Properties: graph.MustProperties(map[string]any{
			"instance_profile": "web-profile",
			"reason":           "Instance profile web-profile attaches role AppRole.",
		}),
	})

	docs := []string{`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::logs","arn:aws:s3:::logs/*"]}}`}
	if err := c.linkRoleS3Access(&batch, "AppRole", docs); err != nil {
		t.Fatal(err)
	}
	if err := c.linkRoleS3Access(&batch, "AppRole", docs); err != nil {
		t.Fatal(err)
	}

	roleID := c.nodeID("identity", "AppRole")
	if !hasEdge(batch, webID, roleID, graph.EdgeAssumes) {
		t.Fatal("missing ASSUMES edge from web-1 to AppRole")
	}
	if !hasEdge(batch, roleID, logsID, graph.EdgeCanAccess) {
		t.Fatal("missing CAN_ACCESS edge from AppRole to logs")
	}
	if hasEdge(batch, roleID, privateID, graph.EdgeCanAccess) {
		t.Fatal("AppRole should not reach private")
	}
	if countEdges(batch, roleID, logsID, graph.EdgeCanAccess) != 1 {
		t.Fatal("duplicate CAN_ACCESS edge")
	}
}

func TestLinkRoleS3AccessStarMatchesEveryBucket(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: c.nodeID("datastore", "logs"), Type: graph.NodeDatastore, Name: "logs", Properties: map[string]any{"service": "s3"}},
			{ID: c.nodeID("datastore", "private"), Type: graph.NodeDatastore, Name: "private", Properties: map[string]any{"service": "s3"}},
			{ID: c.nodeID("datastore", "db"), Type: graph.NodeDatastore, Name: "prod-db", Properties: map[string]any{"service": "rds"}},
		},
	}
	docs := []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}
	if err := c.linkRoleS3Access(&batch, "AdminRole", docs); err != nil {
		t.Fatal(err)
	}
	roleID := c.nodeID("identity", "AdminRole")
	if !hasEdge(batch, roleID, c.nodeID("datastore", "logs"), graph.EdgeCanAccess) {
		t.Fatal("expected access to logs")
	}
	if !hasEdge(batch, roleID, c.nodeID("datastore", "private"), graph.EdgeCanAccess) {
		t.Fatal("expected access to private")
	}
	if hasEdge(batch, roleID, c.nodeID("datastore", "db"), graph.EdgeCanAccess) {
		t.Fatal("RDS datastore should not match an S3 grant")
	}
}

func hasEdge(batch graph.Batch, source, target, edgeType string) bool {
	return countEdges(batch, source, target, edgeType) > 0
}

func countEdges(batch graph.Batch, source, target, edgeType string) int {
	n := 0
	for _, edge := range batch.Edges {
		if edge.SourceID == source && edge.TargetID == target && edge.Type == edgeType {
			n++
		}
	}
	return n
}
