// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/OpenSourceOM/core/internal/graph"
)

// Well-known built-in role definition ids. These are stable across tenants.
// Admin and storage decisions use the role name and actions, not a substring of the id.
const (
	azureRoleOwner                      = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	azureRoleContributor                = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	azureRoleReader                     = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	azureRoleUserAccessAdmin            = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
	azureRoleStorageBlobDataReader      = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	azureRoleStorageBlobDataContributor = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)

// azureIdentityUse is a workload and a managed identity it runs as.
type azureIdentityUse struct {
	WorkloadID  string
	PrincipalID string
}

// azureAssignment is one role assignment. A non-empty Condition means the
// grant is not unconditional, so it does not set admin_access or CAN_ACCESS.
type azureAssignment struct {
	ID               string
	PrincipalID      string
	RoleDefinitionID string
	Scope            string
	Condition        string
}

type azurePermission struct {
	Actions        []string
	NotActions     []string
	DataActions    []string
	NotDataActions []string
}

type azureRole struct {
	Name        string
	Permissions []azurePermission
}

// linkAzureAccess adds identity nodes, ASSUMES edges from each VM to the
// managed identities it runs as, and CAN_ACCESS edges from those identities to
// storage accounts their role assignments cover. Conditional assignments are
// ignored. NotActions are evaluated per permission entry.
func (c *Collector) linkAzureAccess(batch *graph.Batch, uses []azureIdentityUse, assignments []azureAssignment, roles map[string]azureRole) {
	principals := map[string]struct{}{}
	for _, use := range uses {
		if use.PrincipalID != "" {
			principals[use.PrincipalID] = struct{}{}
		}
	}
	for _, assignment := range assignments {
		if assignment.PrincipalID != "" {
			principals[assignment.PrincipalID] = struct{}{}
		}
	}
	for principalID := range principals {
		c.ensureAzureIdentity(batch, principalID)
	}

	for _, use := range uses {
		if use.WorkloadID == "" || use.PrincipalID == "" {
			continue
		}
		identityID := c.nodeID("identity", use.PrincipalID)
		workloadName := nodeName(batch, use.WorkloadID)
		addEdge(batch, graph.Edge{
			ID:       c.edgeID(use.WorkloadID, identityID, graph.EdgeAssumes),
			SourceID: use.WorkloadID,
			TargetID: identityID,
			Type:     graph.EdgeAssumes,
			Properties: graph.MustProperties(map[string]any{
				"reason": "Virtual machine " + workloadName + " runs as " + use.PrincipalID + ".",
			}),
		})
	}

	type identityChoice struct {
		roleDefinitionID string
		adminRoleID      string
		admin            bool
	}
	choices := map[string]identityChoice{}
	for _, assignment := range assignments {
		if assignment.PrincipalID == "" || assignment.Condition != "" {
			continue
		}
		role, ok := roles[roleDefinitionGUID(assignment.RoleDefinitionID)]
		if !ok {
			continue
		}
		choice := choices[assignment.PrincipalID]
		if choice.roleDefinitionID == "" {
			choice.roleDefinitionID = assignment.RoleDefinitionID
		}
		if azureRoleGrantsAdmin(role) {
			choice.admin = true
			if choice.adminRoleID == "" {
				choice.adminRoleID = assignment.RoleDefinitionID
			}
		}
		choices[assignment.PrincipalID] = choice

		if !azureRoleGrantsStorage(role) || assignment.Scope == "" {
			continue
		}
		identityID := c.nodeID("identity", assignment.PrincipalID)
		for _, node := range batch.Nodes {
			resourceID, ok := datastoreResourceID(node)
			if !ok || !scopeCoversResource(assignment.Scope, resourceID) {
				continue
			}
			addEdge(batch, graph.Edge{
				ID:       c.edgeID(identityID, node.ID, graph.EdgeCanAccess),
				SourceID: identityID,
				TargetID: node.ID,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"reason": "Role " + role.Name + " on " + assignment.Scope + " allows access to " + node.Name + ".",
				}),
			})
		}
	}

	for principalID, choice := range choices {
		roleID := choice.adminRoleID
		if roleID == "" {
			roleID = choice.roleDefinitionID
		}
		c.setAzureIdentity(batch, principalID, roleID, choice.admin)
	}
}

func vmIdentityUses(workloadID string, identity *armcompute.VirtualMachineIdentity) []azureIdentityUse {
	if identity == nil || workloadID == "" {
		return nil
	}
	seen := map[string]bool{}
	var uses []azureIdentityUse
	add := func(principalID string) {
		if principalID == "" || seen[principalID] {
			return
		}
		seen[principalID] = true
		uses = append(uses, azureIdentityUse{WorkloadID: workloadID, PrincipalID: principalID})
	}
	add(safeString(identity.PrincipalID))
	for _, assigned := range identity.UserAssignedIdentities {
		if assigned == nil {
			continue
		}
		add(safeString(assigned.PrincipalID))
	}
	return uses
}

func assignmentFromRole(item *armauthorization.RoleAssignment) (azureAssignment, bool) {
	if item == nil || item.Properties == nil {
		return azureAssignment{}, false
	}
	principalID := safeString(item.Properties.PrincipalID)
	roleID := safeString(item.Properties.RoleDefinitionID)
	if principalID == "" || roleID == "" {
		return azureAssignment{}, false
	}
	return azureAssignment{
		ID:               safeString(item.ID),
		PrincipalID:      principalID,
		RoleDefinitionID: roleID,
		Scope:            safeString(item.Properties.Scope),
		Condition:        strings.TrimSpace(safeString(item.Properties.Condition)),
	}, true
}

func azureRoleFromDefinition(def armauthorization.RoleDefinition) azureRole {
	role := azureRole{}
	if def.Properties == nil {
		return role
	}
	role.Name = safeString(def.Properties.RoleName)
	for _, perm := range def.Properties.Permissions {
		if perm == nil {
			continue
		}
		role.Permissions = append(role.Permissions, azurePermission{
			Actions:        derefStrings(perm.Actions),
			NotActions:     derefStrings(perm.NotActions),
			DataActions:    derefStrings(perm.DataActions),
			NotDataActions: derefStrings(perm.NotDataActions),
		})
	}
	return role
}

func builtinAzureRole(roleDefinitionID string) (azureRole, bool) {
	switch roleDefinitionGUID(roleDefinitionID) {
	case azureRoleOwner:
		return azureRole{Name: "Owner", Permissions: []azurePermission{{Actions: []string{"*"}}}}, true
	case azureRoleContributor:
		return azureRole{
			Name: "Contributor",
			Permissions: []azurePermission{{
				Actions: []string{"*"},
				NotActions: []string{
					"Microsoft.Authorization/*/Delete",
					"Microsoft.Authorization/*/Write",
					"Microsoft.Authorization/elevateAccess/Action",
				},
			}},
		}, true
	case azureRoleReader:
		return azureRole{Name: "Reader", Permissions: []azurePermission{{Actions: []string{"*/read"}}}}, true
	case azureRoleUserAccessAdmin:
		return azureRole{
			Name: "User Access Administrator",
			Permissions: []azurePermission{{
				Actions: []string{"*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"},
			}},
		}, true
	case azureRoleStorageBlobDataReader:
		return azureRole{
			Name: "Storage Blob Data Reader",
			Permissions: []azurePermission{{
				DataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
			}},
		}, true
	case azureRoleStorageBlobDataContributor:
		return azureRole{
			Name: "Storage Blob Data Contributor",
			Permissions: []azurePermission{{
				DataActions: []string{
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
				},
			}},
		}, true
	default:
		return azureRole{}, false
	}
}

func azureRoleGrantsAdmin(role azureRole) bool {
	switch strings.ToLower(strings.TrimSpace(role.Name)) {
	case "owner", "contributor", "user access administrator":
		return true
	}
	for _, perm := range role.Permissions {
		if azureCovers(perm.Actions, perm.NotActions, "*") {
			return true
		}
		if azureCovers(perm.Actions, perm.NotActions, "Microsoft.Authorization/roleAssignments/write") {
			return true
		}
	}
	return false
}

func azureRoleGrantsStorage(role azureRole) bool {
	reads := []string{
		"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
		"Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
		"Microsoft.Storage/storageAccounts/queueServices/queues/messages/read",
		"Microsoft.Storage/storageAccounts/tableServices/tables/entities/read",
	}
	for _, perm := range role.Permissions {
		if azureCovers(perm.Actions, perm.NotActions, "*") {
			return true
		}
		if azureCovers(perm.Actions, perm.NotActions, "Microsoft.Storage/storageAccounts/listKeys/action") {
			return true
		}
		for _, want := range reads {
			if azureCovers(perm.DataActions, perm.NotDataActions, want) {
				return true
			}
		}
	}
	return false
}

func azureCovers(granted, denied []string, want string) bool {
	if !azureAnyMatch(granted, want) {
		return false
	}
	return !azureAnyMatch(denied, want)
}

func azureAnyMatch(patterns []string, want string) bool {
	for _, pattern := range patterns {
		if azureActionMatch(pattern, want) {
			return true
		}
	}
	return false
}

func azureActionMatch(pattern, want string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	want = strings.ToLower(strings.TrimSpace(want))
	if pattern == "" || want == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(want, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == want
}

func scopeCoversResource(scope, resourceID string) bool {
	scope = strings.TrimRight(strings.ToLower(strings.TrimSpace(scope)), "/")
	resourceID = strings.TrimRight(strings.ToLower(strings.TrimSpace(resourceID)), "/")
	if scope == "" || resourceID == "" {
		return false
	}
	return resourceID == scope || strings.HasPrefix(resourceID, scope+"/")
}

func roleDefinitionGUID(roleDefinitionID string) string {
	id := strings.Trim(strings.TrimSpace(roleDefinitionID), "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return strings.ToLower(id)
}

func datastoreResourceID(node graph.Node) (string, bool) {
	if node.Type != graph.NodeDatastore || node.Properties == nil {
		return "", false
	}
	id, _ := node.Properties["resource_id"].(string)
	if id == "" {
		return "", false
	}
	return id, true
}

func (c *Collector) ensureAzureIdentity(batch *graph.Batch, principalID string) {
	id := c.nodeID("identity", principalID)
	for _, node := range batch.Nodes {
		if node.ID == id {
			return
		}
	}
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID:        id,
		Type:      graph.NodeIdentity,
		Name:      principalID,
		Provider:  "azure",
		Region:    c.Location,
		AccountID: c.SubscriptionID,
		Properties: graph.MustProperties(map[string]any{
			"admin_access": false,
		}),
	})
}

func (c *Collector) setAzureIdentity(batch *graph.Batch, principalID, roleDefinitionID string, admin bool) {
	id := c.nodeID("identity", principalID)
	for i := range batch.Nodes {
		if batch.Nodes[i].ID != id {
			continue
		}
		if batch.Nodes[i].Properties == nil {
			batch.Nodes[i].Properties = map[string]any{}
		}
		batch.Nodes[i].Properties["admin_access"] = admin
		if roleDefinitionID != "" {
			batch.Nodes[i].Properties["role_definition_id"] = roleDefinitionID
		}
		return
	}
}

func addEdge(batch *graph.Batch, edge graph.Edge) {
	for _, existing := range batch.Edges {
		if existing.ID == edge.ID {
			return
		}
	}
	batch.Edges = append(batch.Edges, edge)
}

func nodeName(batch *graph.Batch, id string) string {
	for _, node := range batch.Nodes {
		if node.ID == id && node.Name != "" {
			return node.Name
		}
	}
	return id
}

func derefStrings(vals []*string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != nil && strings.TrimSpace(*v) != "" {
			out = append(out, *v)
		}
	}
	return out
}
