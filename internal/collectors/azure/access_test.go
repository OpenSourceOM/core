// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/OpenSourceOM/core/internal/graph"
)

func TestVMIdentityUses(t *testing.T) {
	uses := vmIdentityUses("vm-1", &armcompute.VirtualMachineIdentity{
		PrincipalID: ptr("system"),
		UserAssignedIdentities: map[string]*armcompute.UserAssignedIdentitiesValue{
			"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app": {
				PrincipalID: ptr("user"),
			},
			"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/empty": {},
		},
	})
	if len(uses) != 2 || uses[0].PrincipalID != "system" || uses[1].PrincipalID != "user" {
		t.Fatalf("uses = %+v", uses)
	}
	if again := vmIdentityUses("vm-1", &armcompute.VirtualMachineIdentity{PrincipalID: ptr("system")}); len(again) != 1 {
		t.Fatalf("system-only uses = %+v", again)
	}
}

func TestWellKnownAzureRoles(t *testing.T) {
	cases := []struct {
		id      string
		admin   bool
		storage bool
	}{
		{azureRoleOwner, true, true},
		{azureRoleContributor, true, true},
		{azureRoleUserAccessAdmin, true, false},
		{azureRoleReader, false, false},
		{azureRoleStorageBlobDataReader, false, true},
	}
	for _, tc := range cases {
		role, ok := builtinAzureRole(tc.id)
		if !ok {
			t.Fatalf("missing built-in role %s", tc.id)
		}
		if got := azureRoleGrantsAdmin(role); got != tc.admin {
			t.Fatalf("%s admin = %v, want %v", role.Name, got, tc.admin)
		}
		if got := azureRoleGrantsStorage(role); got != tc.storage {
			t.Fatalf("%s storage = %v, want %v", role.Name, got, tc.storage)
		}
	}
}

func TestCustomAzureRoleAdmin(t *testing.T) {
	if !azureRoleGrantsAdmin(azureRole{Name: "Custom", Permissions: []azurePermission{{Actions: []string{"*"}}}}) {
		t.Fatal("custom role with * should be admin")
	}
	if !azureRoleGrantsAdmin(azureRole{Name: "Custom UAA", Permissions: []azurePermission{{Actions: []string{"Microsoft.Authorization/roleAssignments/write"}}}}) {
		t.Fatal("custom role that can write role assignments should be admin")
	}
	if azureRoleGrantsAdmin(azureRole{Name: "Custom Reader", Permissions: []azurePermission{{Actions: []string{"*/read"}}}}) {
		t.Fatal("custom role with */read should not be admin")
	}
	if azureRoleGrantsAdmin(azureRole{
		Name: "Cancelled",
		Permissions: []azurePermission{{
			Actions:    []string{"*"},
			NotActions: []string{"*"},
		}},
	}) {
		t.Fatal("NotActions * should cancel Actions *")
	}
}

func TestLinkAzureAccessOneStorageAccount(t *testing.T) {
	c := NewCollector("sub", "eastus")
	webID := c.nodeID("workload", "web")
	logsID := c.nodeID("datastore", "logs")
	otherID := c.nodeID("datastore", "other")
	logsResource := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
	otherResource := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/other"
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: webID, Type: graph.NodeWorkload, Name: "web"},
			{
				ID: logsID, Type: graph.NodeDatastore, Name: "logs",
				Properties: map[string]any{"resource_id": logsResource, "public_access": true},
			},
			{
				ID: otherID, Type: graph.NodeDatastore, Name: "other",
				Properties: map[string]any{"resource_id": otherResource, "public_access": true},
			},
		},
		Edges: []graph.Edge{{
			ID: "reachable", SourceID: graph.InternetNodeID, TargetID: webID, Type: graph.EdgeReachable,
		}},
	}
	roleID := "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/" + azureRoleStorageBlobDataReader
	reader, _ := builtinAzureRole(azureRoleStorageBlobDataReader)
	c.linkAzureAccess(&batch, []azureIdentityUse{{
		WorkloadID: webID, PrincipalID: "principal-1",
	}}, []azureAssignment{{
		PrincipalID: "principal-1", RoleDefinitionID: roleID, Scope: logsResource,
	}}, map[string]azureRole{azureRoleStorageBlobDataReader: reader})
	c.linkAzureAccess(&batch, []azureIdentityUse{{
		WorkloadID: webID, PrincipalID: "principal-1",
	}}, []azureAssignment{{
		PrincipalID: "principal-1", RoleDefinitionID: roleID, Scope: logsResource,
	}}, map[string]azureRole{azureRoleStorageBlobDataReader: reader})

	identityID := c.nodeID("identity", "principal-1")
	if !hasEdge(batch, webID, identityID, graph.EdgeAssumes) {
		t.Fatal("missing ASSUMES edge from web to principal-1")
	}
	if !hasEdge(batch, identityID, logsID, graph.EdgeCanAccess) {
		t.Fatal("missing CAN_ACCESS edge from principal-1 to logs")
	}
	if hasEdge(batch, identityID, otherID, graph.EdgeCanAccess) {
		t.Fatal("principal-1 should not reach other")
	}
	if hasEdge(batch, webID, logsID, graph.EdgeCanAccess) || hasEdge(batch, webID, otherID, graph.EdgeCanAccess) {
		t.Fatal("workload should not be linked to public storage without a role assignment")
	}
	if countEdges(batch, identityID, logsID, graph.EdgeCanAccess) != 1 {
		t.Fatal("duplicate CAN_ACCESS edge")
	}
	identity := findNode(batch, identityID)
	if admin, _ := identity.Properties["admin_access"].(bool); admin {
		t.Fatal("blob data reader should not be admin")
	}
}

func TestLinkAzureAccessAdminFromRoleNotGUID(t *testing.T) {
	c := NewCollector("sub", "eastus")
	logsResource := "/subscriptions/SUB/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
	sqlResourceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/prod"
	batch := graph.Batch{Nodes: []graph.Node{
		{
			ID: c.nodeID("datastore", "logs"), Type: graph.NodeDatastore, Name: "logs",
			Properties: map[string]any{"resource_id": logsResource, "public_access": false},
		},
		{
			ID: c.nodeID("datastore", "prod"), Type: graph.NodeDatastore, Name: "prod",
			Properties: map[string]any{"resource_id": sqlResourceID, "service": "sql", "public_access": false},
		},
	}}
	ownerID := "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/" + azureRoleOwner
	readerID := "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/" + azureRoleReader
	owner, _ := builtinAzureRole(azureRoleOwner)
	reader, _ := builtinAzureRole(azureRoleReader)
	c.linkAzureAccess(&batch, nil, []azureAssignment{
		{PrincipalID: "p1", RoleDefinitionID: readerID, Scope: "/subscriptions/sub"},
		{PrincipalID: "p1", RoleDefinitionID: ownerID, Scope: "/subscriptions/sub"},
	}, map[string]azureRole{
		azureRoleOwner:  owner,
		azureRoleReader: reader,
	})

	identity := findNode(batch, c.nodeID("identity", "p1"))
	if admin, _ := identity.Properties["admin_access"].(bool); !admin {
		t.Fatal("Owner assignment should set admin_access even when a Reader assignment is also present")
	}
	if got, _ := identity.Properties["role_definition_id"].(string); got != ownerID {
		t.Fatalf("role_definition_id = %s, want owner", got)
	}
	if !hasEdge(batch, identity.ID, c.nodeID("datastore", "logs"), graph.EdgeCanAccess) {
		t.Fatal("subscription Owner should reach the storage account, including a private one")
	}
	if hasEdge(batch, identity.ID, c.nodeID("datastore", "prod"), graph.EdgeCanAccess) {
		t.Fatal("subscription Owner storage access should not reach Azure SQL")
	}
}

func TestConditionalAzureAssignmentGrantsNothing(t *testing.T) {
	c := NewCollector("sub", "eastus")
	resource := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
	batch := graph.Batch{Nodes: []graph.Node{{
		ID: c.nodeID("datastore", "logs"), Type: graph.NodeDatastore, Name: "logs",
		Properties: map[string]any{"resource_id": resource},
	}}}
	ownerID := "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/" + azureRoleOwner
	owner, _ := builtinAzureRole(azureRoleOwner)
	c.linkAzureAccess(&batch, nil, []azureAssignment{{
		PrincipalID: "p1", RoleDefinitionID: ownerID, Scope: "/subscriptions/sub", Condition: "@Resource[...]",
	}}, map[string]azureRole{azureRoleOwner: owner})

	identity := findNode(batch, c.nodeID("identity", "p1"))
	if admin, _ := identity.Properties["admin_access"].(bool); admin {
		t.Fatal("conditional Owner should not set admin_access")
	}
	if hasEdge(batch, identity.ID, c.nodeID("datastore", "logs"), graph.EdgeCanAccess) {
		t.Fatal("conditional Owner should not grant CAN_ACCESS")
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
