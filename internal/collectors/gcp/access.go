// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
)

// gcpPrincipal is a service account in the project.
type gcpPrincipal struct {
	Email    string
	UniqueID string
}

// gcpInstanceSA is a GCE instance and a service account attached to it.
type gcpInstanceSA struct {
	WorkloadID string
	Email      string
}

// gcpBinding is one IAM binding member. Bucket empty means the binding is on
// the project. Conditional bindings are not treated as access.
type gcpBinding struct {
	Role        string
	Member      string
	Bucket      string
	Conditional bool
	Permissions []string
}

// linkGCPAccess adds service-account identity nodes, ASSUMES edges from each
// instance to the service account it runs as, and CAN_ACCESS edges from those
// identities to buckets granted by project or bucket IAM. The account name is
// not used. Conditional bindings are ignored.
func (c *Collector) linkGCPAccess(batch *graph.Batch, accounts []gcpPrincipal, uses []gcpInstanceSA, bindings []gcpBinding) {
	byEmail := map[string]gcpPrincipal{}
	for _, account := range accounts {
		email := strings.ToLower(strings.TrimSpace(account.Email))
		if email == "" {
			continue
		}
		account.Email = email
		byEmail[email] = account
	}
	for _, use := range uses {
		email := strings.ToLower(strings.TrimSpace(use.Email))
		if email == "" {
			continue
		}
		if _, ok := byEmail[email]; !ok {
			byEmail[email] = gcpPrincipal{Email: email}
		}
	}
	for _, binding := range bindings {
		email, ok := serviceAccountEmail(binding.Member)
		if !ok {
			continue
		}
		if _, exists := byEmail[email]; !exists {
			byEmail[email] = gcpPrincipal{Email: email}
		}
	}

	idByEmail := map[string]string{}
	for email, account := range byEmail {
		id := c.ensureGCPIdentity(batch, account)
		idByEmail[email] = id
	}

	for _, use := range uses {
		email := strings.ToLower(strings.TrimSpace(use.Email))
		identityID := idByEmail[email]
		if use.WorkloadID == "" || identityID == "" {
			continue
		}
		addEdge(batch, graph.Edge{
			ID:       c.edgeID(use.WorkloadID, identityID, graph.EdgeAssumes),
			SourceID: use.WorkloadID,
			TargetID: identityID,
			Type:     graph.EdgeAssumes,
			Properties: graph.MustProperties(map[string]any{
				"reason": "Instance " + nodeName(batch, use.WorkloadID) + " runs as " + email + ".",
			}),
		})
	}

	admin := map[string]bool{}
	for _, binding := range bindings {
		if binding.Conditional {
			continue
		}
		email, ok := serviceAccountEmail(binding.Member)
		if !ok {
			continue
		}
		identityID := idByEmail[email]
		if identityID == "" {
			continue
		}
		if gcpRoleGrantsAdmin(binding.Role, binding.Permissions) {
			admin[identityID] = true
		}
		if !gcpRoleGrantsObjectAccess(binding.Role, binding.Permissions) {
			continue
		}
		for _, node := range batch.Nodes {
			if !gcsDatastore(node) {
				continue
			}
			if binding.Bucket != "" && node.Name != binding.Bucket {
				continue
			}
			reason := "Project IAM grants " + binding.Role + " to " + email + "."
			if binding.Bucket != "" {
				reason = "Bucket IAM grants " + binding.Role + " on " + binding.Bucket + " to " + email + "."
			}
			addEdge(batch, graph.Edge{
				ID:       c.edgeID(identityID, node.ID, graph.EdgeCanAccess),
				SourceID: identityID,
				TargetID: node.ID,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"reason": reason,
				}),
			})
		}
	}
	for id, isAdmin := range admin {
		c.setGCPAdmin(batch, id, isAdmin)
	}
}

func gcpRoleGrantsAdmin(role string, permissions []string) bool {
	switch role {
	case "roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin":
		return true
	}
	for _, permission := range permissions {
		if permission == "resourcemanager.projects.setIamPolicy" {
			return true
		}
	}
	return false
}

func gcpRoleGrantsObjectAccess(role string, permissions []string) bool {
	switch role {
	case "roles/owner", "roles/editor",
		"roles/storage.admin", "roles/storage.objectAdmin", "roles/storage.objectViewer", "roles/storage.objectUser",
		"roles/storage.legacyBucketOwner", "roles/storage.legacyObjectOwner", "roles/storage.legacyObjectReader":
		return true
	}
	for _, permission := range permissions {
		if permission == "storage.objects.get" {
			return true
		}
	}
	return false
}

func gcpCustomRole(role string) bool {
	return strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/")
}

func serviceAccountEmail(member string) (string, bool) {
	const prefix = "serviceAccount:"
	if len(member) <= len(prefix) || !strings.EqualFold(member[:len(prefix)], prefix) {
		return "", false
	}
	email := strings.ToLower(strings.TrimSpace(member[len(prefix):]))
	if email == "" || strings.Contains(email, " ") {
		return "", false
	}
	return email, true
}

func (c *Collector) ensureGCPIdentity(batch *graph.Batch, account gcpPrincipal) string {
	resource := account.UniqueID
	if resource == "" {
		resource = account.Email
	}
	id := c.nodeID(c.Region, "identity", resource)
	for _, node := range batch.Nodes {
		if node.ID == id {
			return id
		}
	}
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID:        id,
		Type:      graph.NodeIdentity,
		Name:      account.Email,
		Provider:  "gcp",
		Region:    c.Region,
		AccountID: c.ProjectID,
		Properties: graph.MustProperties(map[string]any{
			"email":        account.Email,
			"admin_access": false,
		}),
	})
	return id
}

func (c *Collector) setGCPAdmin(batch *graph.Batch, id string, admin bool) {
	for i := range batch.Nodes {
		if batch.Nodes[i].ID != id {
			continue
		}
		if batch.Nodes[i].Properties == nil {
			batch.Nodes[i].Properties = map[string]any{}
		}
		batch.Nodes[i].Properties["admin_access"] = admin
		return
	}
}

func gcsDatastore(node graph.Node) bool {
	if node.Type != graph.NodeDatastore || node.Name == "" {
		return false
	}
	service, _ := node.Properties["service"].(string)
	return service == "" || service == "gcs"
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
