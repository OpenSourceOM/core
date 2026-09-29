// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

func TestAzureSQLFollowsNetworkPath(t *testing.T) {
	c := NewCollector("sub", "eastus")
	subnet := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"
	otherSubnet := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/data"
	servers := []*armresources.GenericResourceExpanded{
		sqlResource("prod", "Microsoft.Sql/servers", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/prod", map[string]any{
			"publicNetworkAccess": "Enabled",
		}),
		sqlResource("private", "Microsoft.Sql/servers", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/private", map[string]any{
			"publicNetworkAccess": "Disabled",
		}),
		sqlResource("wide", "Microsoft.Sql/servers", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/wide", map[string]any{
			"publicNetworkAccess": "Enabled",
		}),
	}
	firewalls := []*armresources.GenericResourceExpanded{
		sqlResource("office", "Microsoft.Sql/servers/firewallRules", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/prod/firewallRules/office", map[string]any{
			"startIpAddress": "203.0.113.10",
			"endIpAddress":   "203.0.113.20",
		}),
		sqlResource("azure", "Microsoft.Sql/servers/firewallRules", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/prod/firewallRules/azure", map[string]any{
			"startIpAddress": "0.0.0.0",
			"endIpAddress":   "0.0.0.0",
		}),
		sqlResource("open", "Microsoft.Sql/servers/firewallRules", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/wide/firewallRules/open", map[string]any{
			"startIpAddress": "0.0.0.0",
			"endIpAddress":   "255.255.255.255",
		}),
		sqlResource("ignored", "Microsoft.Sql/servers/firewallRules", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/private/firewallRules/open", map[string]any{
			"startIpAddress": "0.0.0.0",
			"endIpAddress":   "255.255.255.255",
		}),
	}
	vnets := []*armresources.GenericResourceExpanded{
		sqlResource("app", "Microsoft.Sql/servers/virtualNetworkRules", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/private/virtualNetworkRules/app", map[string]any{
			"virtualNetworkSubnetId": subnet,
		}),
	}
	model := assembleSQLServers(servers, firewalls, vnets)
	var batch graph.Batch
	batch.Nodes = append(batch.Nodes,
		graph.Node{ID: c.nodeID("workload", "web"), Type: graph.NodeWorkload, Name: "web"},
		graph.Node{ID: c.nodeID("workload", "worker"), Type: graph.NodeWorkload, Name: "worker"},
		graph.Node{ID: c.nodeID("workload", "other"), Type: graph.NodeWorkload, Name: "other"},
	)
	c.addSQLNodes(&batch, model)
	c.linkAzureSQL(&batch, model, []azureWorkloadNet{
		{WorkloadID: c.nodeID("workload", "web"), PublicIPs: []string{"203.0.113.15"}},
		{WorkloadID: c.nodeID("workload", "worker"), SubnetIDs: []string{subnet}},
		{WorkloadID: c.nodeID("workload", "other"), PublicIPs: []string{"198.51.100.8"}, SubnetIDs: []string{otherSubnet}},
	})

	prodID := c.nodeID("datastore", "prod")
	privateID := c.nodeID("datastore", "private")
	wideID := c.nodeID("datastore", "wide")
	assertPublic := func(id string, want bool) {
		t.Helper()
		node := findNode(batch, id)
		if node.ID == "" {
			t.Fatalf("missing %s", id)
		}
		if node.Properties["service"] != "sql" {
			t.Fatalf("%s service = %v", id, node.Properties["service"])
		}
		if got, _ := node.Properties["public_access"].(bool); got != want {
			t.Fatalf("%s public_access = %v, want %v", node.Name, got, want)
		}
	}
	assertPublic(prodID, false)
	assertPublic(privateID, false)
	assertPublic(wideID, true)

	web := c.nodeID("workload", "web")
	worker := c.nodeID("workload", "worker")
	other := c.nodeID("workload", "other")
	if !hasEdge(batch, web, prodID, graph.EdgeCanAccess) {
		t.Fatal("web's public IP is inside the office firewall range")
	}
	if hasEdge(batch, other, prodID, graph.EdgeCanAccess) {
		t.Fatal("a different public IP should not match the office range")
	}
	if hasEdge(batch, worker, prodID, graph.EdgeCanAccess) {
		t.Fatal("Allow Azure services is not a path from a VM")
	}
	if !hasEdge(batch, worker, privateID, graph.EdgeCanAccess) {
		t.Fatal("worker should reach the private server through its subnet rule")
	}
	if hasEdge(batch, web, privateID, graph.EdgeCanAccess) || hasEdge(batch, other, privateID, graph.EdgeCanAccess) {
		t.Fatal("a disabled public endpoint and a different subnet are not a path")
	}
	if !hasEdge(batch, web, wideID, graph.EdgeCanAccess) || !hasEdge(batch, other, wideID, graph.EdgeCanAccess) {
		t.Fatal("a wide-open firewall should allow every VM that has a public IP")
	}
	if hasEdge(batch, worker, wideID, graph.EdgeCanAccess) {
		t.Fatal("a VM without a public IP is not on the wide-open firewall path")
	}
}

func sqlResource(name, resourceType, id string, props map[string]any) *armresources.GenericResourceExpanded {
	return &armresources.GenericResourceExpanded{
		Name:       &name,
		Type:       &resourceType,
		ID:         &id,
		Location:   ptr("eastus"),
		Properties: props,
	}
}
