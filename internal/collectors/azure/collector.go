// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

type Collector struct {
	SubscriptionID string
	Location       string
}

func NewCollector(subscriptionID, location string) *Collector {
	return &Collector{
		SubscriptionID: subscriptionID,
		Location:       location,
	}
}

func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	if c.SubscriptionID == "" {
		return graph.Batch{}, fmt.Errorf("AZURE_SUBSCRIPTION_ID is required")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return graph.Batch{}, fmt.Errorf("azure credentials: %w", err)
	}

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:       graph.InternetNodeID,
				Type:     graph.NodeInternet,
				Name:     "Internet",
				Provider: "azure",
			},
		},
	}

	if err := c.collectVMs(ctx, cred, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectStorage(ctx, cred, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectRBAC(ctx, cred, &batch); err != nil {
		return graph.Batch{}, err
	}

	c.linkInternetWorkloadsToPublicDatastores(&batch)
	return batch, nil
}

func (c *Collector) collectVMs(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) error {
	rgClient, err := armresources.NewResourceGroupsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}

	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list resource groups: %w", err)
		}
		for _, rg := range page.Value {
			if rg.Name == nil {
				continue
			}
			vmPager := vmClient.NewListPager(*rg.Name, nil)
			for vmPager.More() {
				vmPage, err := vmPager.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("list vms: %w", err)
				}
				for _, vm := range vmPage.Value {
					if vm.Name == nil || vm.ID == nil {
						continue
					}
					workloadID := c.nodeID("workload", *vm.Name)
					location := c.Location
					if vm.Location != nil {
						location = *vm.Location
					}

					publicIP := ""
					if vm.Properties != nil && vm.Properties.NetworkProfile != nil {
						for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
							_ = nicRef
						}
					}

					batch.Nodes = append(batch.Nodes, graph.Node{
						ID:        workloadID,
						Type:      graph.NodeWorkload,
						Name:      *vm.Name,
						Provider:  "azure",
						Region:    location,
						AccountID: c.SubscriptionID,
						Properties: graph.MustProperties(map[string]any{
							"resource_id": *vm.ID,
							"public_ip":   publicIP,
						}),
					})

					if publicIP != "" {
						batch.Edges = append(batch.Edges, graph.Edge{
							ID:       c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
							SourceID: graph.InternetNodeID,
							TargetID: workloadID,
							Type:     graph.EdgeReachable,
						})
					}
				}
			}
		}
	}
	return nil
}

func (c *Collector) collectStorage(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) error {
	client, err := armstorage.NewAccountsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list storage accounts: %w", err)
		}
		for _, account := range page.Value {
			if account.Name == nil {
				continue
			}
			location := c.Location
			if account.Location != nil {
				location = *account.Location
			}
			publicAccess := false
			if account.Properties != nil && account.Properties.AllowBlobPublicAccess != nil {
				publicAccess = *account.Properties.AllowBlobPublicAccess
			}

			datastoreID := c.nodeID("datastore", *account.Name)
			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        datastoreID,
				Type:      graph.NodeDatastore,
				Name:      *account.Name,
				Provider:  "azure",
				Region:    location,
				AccountID: c.SubscriptionID,
				Properties: graph.MustProperties(map[string]any{
					"resource_id":   safeString(account.ID),
					"public_access": publicAccess,
				}),
			})
		}
	}
	return nil
}

func (c *Collector) collectRBAC(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) error {
	client, err := armauthorization.NewRoleAssignmentsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}

	scope := fmt.Sprintf("/subscriptions/%s", c.SubscriptionID)
	pager := client.NewListForScopePager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list role assignments: %w", err)
		}
		for _, assignment := range page.Value {
			if assignment.Properties == nil || assignment.Properties.RoleDefinitionID == nil {
				continue
			}
			roleDefID := *assignment.Properties.RoleDefinitionID
			principalID := safeString(assignment.Properties.PrincipalID)
			if principalID == "" {
				continue
			}

			adminAccess := roleLooksAdministrative(roleDefID)
			identityID := c.nodeID("identity", principalID)
			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        identityID,
				Type:      graph.NodeIdentity,
				Name:      principalID,
				Provider:  "azure",
				Region:    c.Location,
				AccountID: c.SubscriptionID,
				Properties: graph.MustProperties(map[string]any{
					"role_definition_id": roleDefID,
					"admin_access":       adminAccess,
				}),
			})
		}
	}
	return nil
}

func (c *Collector) linkInternetWorkloadsToPublicDatastores(batch *graph.Batch) {
	internetWorkloads := map[string]bool{}
	for _, edge := range batch.Edges {
		if edge.SourceID == graph.InternetNodeID && edge.Type == graph.EdgeReachable {
			internetWorkloads[edge.TargetID] = true
		}
	}

	var publicDatastores []graph.Node
	for _, node := range batch.Nodes {
		if node.Type != graph.NodeDatastore {
			continue
		}
		public, _ := node.Properties["public_access"].(bool)
		if public {
			publicDatastores = append(publicDatastores, node)
		}
	}

	for _, node := range batch.Nodes {
		if node.Type != graph.NodeIdentity {
			continue
		}
		admin, _ := node.Properties["admin_access"].(bool)
		if !admin {
			continue
		}
		for _, datastore := range publicDatastores {
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(node.ID, datastore.ID, graph.EdgeCanAccess),
				SourceID: node.ID,
				TargetID: datastore.ID,
				Type:     graph.EdgeCanAccess,
			})
		}
	}

	for _, node := range batch.Nodes {
		if node.Type != graph.NodeWorkload || !internetWorkloads[node.ID] {
			continue
		}
		for _, datastore := range publicDatastores {
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(node.ID, datastore.ID, graph.EdgeCanAccess),
				SourceID: node.ID,
				TargetID: datastore.ID,
				Type:     graph.EdgeCanAccess,
			})
		}
	}
}

func (c *Collector) nodeID(kind, resource string) string {
	return fmt.Sprintf("azure:%s:%s:%s:%s", c.SubscriptionID, c.Location, kind, resource)
}

func (c *Collector) edgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, edgeType)
}

func roleLooksAdministrative(roleDefinitionID string) bool {
	lower := strings.ToLower(roleDefinitionID)
	keywords := []string{"owner", "contributor", "admin", "useraccessadministrator"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func safeString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
