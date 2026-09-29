// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
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

	uses, err := c.collectVMs(ctx, cred, &batch)
	if err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectStorage(ctx, cred, &batch); err != nil {
		return graph.Batch{}, err
	}
	assignments, err := c.collectRoleAssignments(ctx, cred, &batch)
	if err != nil {
		return graph.Batch{}, err
	}
	roles, err := c.resolveRoleDefinitions(ctx, cred, assignments)
	if err != nil {
		return graph.Batch{}, err
	}
	c.linkAzureAccess(&batch, uses, assignments, roles)
	return batch, nil
}

func (c *Collector) collectVMs(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) ([]azureIdentityUse, error) {
	rgClient, err := armresources.NewResourceGroupsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	nicClient, err := armnetwork.NewInterfacesClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	pipClient, err := armnetwork.NewPublicIPAddressesClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	networkAPI := armNetworkAPI{nics: nicClient, pips: pipClient}
	nsgs, err := c.listSecurityGroups(ctx, cred)
	if err != nil {
		return nil, err
	}
	lbs, err := c.listLoadBalancers(ctx, cred)
	if err != nil {
		return nil, err
	}
	vnets, err := c.listVirtualNetworks(ctx, cred)
	if err != nil {
		return nil, err
	}
	nsgByID := indexSecurityGroups(nsgs)
	lbTargets := azurePublicLBTargets(lbs)
	subnetNSG := subnetNSGIndex(vnets)
	seenNetwork := map[string]struct{}{}

	var uses []azureIdentityUse
	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list resource groups: %w", err)
		}
		for _, rg := range page.Value {
			if rg.Name == nil {
				continue
			}
			vmPager := vmClient.NewListPager(*rg.Name, nil)
			for vmPager.More() {
				vmPage, err := vmPager.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list vms: %w", err)
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

					nics, err := readVMNetwork(ctx, networkAPI, vm, subnetNSG)
					if err != nil {
						return nil, err
					}
					publicIP := ""
					for _, nic := range nics {
						if nic.PublicIP != "" {
							publicIP = nic.PublicIP
							break
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

					if err := c.attachAzureExposure(batch, workloadID, nics, nsgByID, lbTargets, seenNetwork); err != nil {
						return nil, err
					}
					uses = append(uses, vmIdentityUses(workloadID, vm.Identity)...)
				}
			}
		}
	}
	return uses, nil
}

func (c *Collector) listSecurityGroups(ctx context.Context, cred azcore.TokenCredential) ([]*armnetwork.SecurityGroup, error) {
	client, err := armnetwork.NewSecurityGroupsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	var groups []*armnetwork.SecurityGroup
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list network security groups: %w", err)
		}
		groups = append(groups, page.Value...)
	}
	return groups, nil
}

func (c *Collector) listLoadBalancers(ctx context.Context, cred azcore.TokenCredential) ([]*armnetwork.LoadBalancer, error) {
	client, err := armnetwork.NewLoadBalancersClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	var lbs []*armnetwork.LoadBalancer
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list load balancers: %w", err)
		}
		lbs = append(lbs, page.Value...)
	}
	return lbs, nil
}

func (c *Collector) listVirtualNetworks(ctx context.Context, cred azcore.TokenCredential) ([]*armnetwork.VirtualNetwork, error) {
	client, err := armnetwork.NewVirtualNetworksClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	var vnets []*armnetwork.VirtualNetwork
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list virtual networks: %w", err)
		}
		vnets = append(vnets, page.Value...)
	}
	return vnets, nil
}

func (c *Collector) collectStorage(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) error {
	client, err := armstorage.NewAccountsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}
	containerClient, err := armstorage.NewBlobContainersClient(c.SubscriptionID, cred, nil)
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
			publicAccess, err := c.storagePublicAccess(ctx, containerClient, account)
			if err != nil {
				return err
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

func (c *Collector) storagePublicAccess(ctx context.Context, client *armstorage.BlobContainersClient, account *armstorage.Account) (bool, error) {
	var allow *bool
	if account.Properties != nil {
		allow = account.Properties.AllowBlobPublicAccess
	}
	if allow != nil && !*allow {
		return false, nil
	}
	resourceGroup, ok := azureResourceGroup(safeString(account.ID))
	if !ok {
		return false, fmt.Errorf("storage account %s: missing resource group", safeString(account.Name))
	}
	var containers []*armstorage.ListContainerItem
	pager := client.NewListPager(resourceGroup, safeString(account.Name), nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false, fmt.Errorf("list containers for %s: %w", safeString(account.Name), err)
		}
		containers = append(containers, page.Value...)
	}
	return azureBlobPublic(allow, containers), nil
}

func (c *Collector) collectRoleAssignments(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch) ([]azureAssignment, error) {
	client, err := armauthorization.NewRoleAssignmentsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	scopes := []string{fmt.Sprintf("/subscriptions/%s", c.SubscriptionID)}
	for _, node := range batch.Nodes {
		if id, ok := datastoreResourceID(node); ok {
			scopes = append(scopes, id)
		}
	}

	seen := map[string]bool{}
	var assignments []azureAssignment
	for _, scope := range scopes {
		pager := client.NewListForScopePager(scope, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("list role assignments at %s: %w", scope, err)
			}
			for _, item := range page.Value {
				assignment, ok := assignmentFromRole(item)
				if !ok {
					continue
				}
				key := assignment.ID
				if key == "" {
					key = assignment.PrincipalID + "|" + assignment.RoleDefinitionID + "|" + assignment.Scope
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				assignments = append(assignments, assignment)
			}
		}
	}
	return assignments, nil
}

func (c *Collector) resolveRoleDefinitions(ctx context.Context, cred azcore.TokenCredential, assignments []azureAssignment) (map[string]azureRole, error) {
	roles := map[string]azureRole{}
	var client *armauthorization.RoleDefinitionsClient
	for _, assignment := range assignments {
		guid := roleDefinitionGUID(assignment.RoleDefinitionID)
		if guid == "" {
			continue
		}
		if _, ok := roles[guid]; ok {
			continue
		}
		if role, ok := builtinAzureRole(guid); ok {
			roles[guid] = role
			continue
		}
		if client == nil {
			var err error
			client, err = armauthorization.NewRoleDefinitionsClient(cred, nil)
			if err != nil {
				return nil, err
			}
		}
		resp, err := client.GetByID(ctx, assignment.RoleDefinitionID, nil)
		if err != nil {
			return nil, fmt.Errorf("get role definition %s: %w", assignment.RoleDefinitionID, err)
		}
		roles[guid] = azureRoleFromDefinition(resp.RoleDefinition)
	}
	return roles, nil
}

func (c *Collector) nodeID(kind, resource string) string {
	return fmt.Sprintf("azure:%s:%s:%s:%s", c.SubscriptionID, c.Location, kind, resource)
}

func (c *Collector) edgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, edgeType)
}

func safeString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
