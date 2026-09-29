// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestLinkGCPInstanceToOneBucket(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	webID := c.nodeID("us-central1-a", "workload", "web")
	logsID := c.nodeID("us-central1", "datastore", "logs")
	otherID := c.nodeID("us-central1", "datastore", "other")
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: webID, Type: graph.NodeWorkload, Name: "web"},
			{ID: logsID, Type: graph.NodeDatastore, Name: "logs", Properties: map[string]any{"public_access": true}},
			{ID: otherID, Type: graph.NodeDatastore, Name: "other", Properties: map[string]any{"public_access": true}},
		},
		Edges: []graph.Edge{{
			ID: "reachable", SourceID: graph.InternetNodeID, TargetID: webID, Type: graph.EdgeReachable,
		}},
	}
	email := "app@proj.iam.gserviceaccount.com"
	c.linkGCPAccess(&batch, []gcpPrincipal{{
		Email: email, UniqueID: "111",
	}}, []gcpInstanceSA{{
		WorkloadID: webID, Email: email,
	}}, []gcpBinding{{
		Role: "roles/storage.objectViewer", Member: "serviceAccount:" + email, Bucket: "logs",
	}})
	c.linkGCPAccess(&batch, []gcpPrincipal{{
		Email: email, UniqueID: "111",
	}}, []gcpInstanceSA{{
		WorkloadID: webID, Email: email,
	}}, []gcpBinding{{
		Role: "roles/storage.objectViewer", Member: "serviceAccount:" + email, Bucket: "logs",
	}})

	identityID := c.nodeID("us-central1", "identity", "111")
	if !hasEdge(batch, webID, identityID, graph.EdgeAssumes) {
		t.Fatal("missing ASSUMES edge from web to the service account")
	}
	if !hasEdge(batch, identityID, logsID, graph.EdgeCanAccess) {
		t.Fatal("missing CAN_ACCESS edge from the service account to logs")
	}
	if hasEdge(batch, identityID, otherID, graph.EdgeCanAccess) {
		t.Fatal("service account should not reach other")
	}
	if hasEdge(batch, webID, logsID, graph.EdgeCanAccess) || hasEdge(batch, webID, otherID, graph.EdgeCanAccess) {
		t.Fatal("instance should not be linked to public buckets without an IAM binding")
	}
	if countEdges(batch, identityID, logsID, graph.EdgeCanAccess) != 1 {
		t.Fatal("duplicate CAN_ACCESS edge")
	}
	identity := findNode(batch, identityID)
	if admin, _ := identity.Properties["admin_access"].(bool); admin {
		t.Fatal("objectViewer should not be admin")
	}
}

func TestGCPAdminComesFromProjectIAM(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	batch := graph.Batch{Nodes: []graph.Node{
		{ID: c.nodeID("us-central1", "datastore", "logs"), Type: graph.NodeDatastore, Name: "logs"},
		{ID: c.nodeID("us-central1", "datastore", "other"), Type: graph.NodeDatastore, Name: "other"},
	}}
	email := "admin@proj.iam.gserviceaccount.com"
	c.linkGCPAccess(&batch, []gcpPrincipal{{Email: email, UniqueID: "222"}}, nil, nil)
	identity := findNode(batch, c.nodeID("us-central1", "identity", "222"))
	if admin, _ := identity.Properties["admin_access"].(bool); admin {
		t.Fatal("an account named admin should not be admin without a binding")
	}

	c.linkGCPAccess(&batch, []gcpPrincipal{{Email: email, UniqueID: "222"}}, nil, []gcpBinding{{
		Role: "roles/owner", Member: "serviceAccount:" + email,
	}})
	identity = findNode(batch, c.nodeID("us-central1", "identity", "222"))
	if admin, _ := identity.Properties["admin_access"].(bool); !admin {
		t.Fatal("roles/owner should set admin_access")
	}
	if !hasEdge(batch, identity.ID, c.nodeID("us-central1", "datastore", "logs"), graph.EdgeCanAccess) {
		t.Fatal("project owner should reach logs")
	}
	if !hasEdge(batch, identity.ID, c.nodeID("us-central1", "datastore", "other"), graph.EdgeCanAccess) {
		t.Fatal("project owner should reach other")
	}
}

func TestGCPConditionalBindingGrantsNothing(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	batch := graph.Batch{Nodes: []graph.Node{{
		ID: c.nodeID("us-central1", "datastore", "logs"), Type: graph.NodeDatastore, Name: "logs",
	}}}
	email := "app@proj.iam.gserviceaccount.com"
	c.linkGCPAccess(&batch, []gcpPrincipal{{Email: email, UniqueID: "333"}}, nil, []gcpBinding{{
		Role: "roles/owner", Member: "serviceAccount:" + email, Conditional: true,
	}})
	identity := findNode(batch, c.nodeID("us-central1", "identity", "333"))
	if admin, _ := identity.Properties["admin_access"].(bool); admin {
		t.Fatal("conditional owner should not set admin_access")
	}
	if hasEdge(batch, identity.ID, c.nodeID("us-central1", "datastore", "logs"), graph.EdgeCanAccess) {
		t.Fatal("conditional owner should not grant CAN_ACCESS")
	}
}

func TestGCPCustomRoleStorageAndAdmin(t *testing.T) {
	if gcpRoleGrantsAdmin("projects/proj/roles/custom", []string{"resourcemanager.projects.setIamPolicy"}) != true {
		t.Fatal("setIamPolicy should be admin")
	}
	if gcpRoleGrantsObjectAccess("projects/proj/roles/custom", []string{"storage.objects.get"}) != true {
		t.Fatal("storage.objects.get should grant object access")
	}
	if gcpRoleGrantsAdmin("roles/viewer", nil) || gcpRoleGrantsObjectAccess("roles/viewer", nil) {
		t.Fatal("roles/viewer should not be admin or object access")
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

func findNode(batch graph.Batch, id string) graph.Node {
	for _, node := range batch.Nodes {
		if node.ID == id {
			return node
		}
	}
	return graph.Node{}
}
