// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

func TestVMPublicIPFromNIC(t *testing.T) {
	const (
		nicID = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1"
		pipID = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip1"
	)
	api := fakeAzureNetwork{
		nics: map[string]armnetwork.Interface{
			"rg1/nic1": {
				Properties: &armnetwork.InterfacePropertiesFormat{
					IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{
						Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
							PublicIPAddress: &armnetwork.PublicIPAddress{ID: ptr(pipID)},
						},
					}},
				},
			},
		},
		pips: map[string]armnetwork.PublicIPAddress{
			"rg1/pip1": {
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: ptr("20.1.2.3")},
			},
		},
	}
	vm := &armcompute.VirtualMachine{
		Properties: &armcompute.VirtualMachineProperties{
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: ptr(nicID)}},
			},
		},
	}
	ip, err := vmPublicIP(context.Background(), api, vm)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "20.1.2.3" {
		t.Fatalf("public ip = %q", ip)
	}

	privateNIC := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic-private"
	api.nics["rg1/nic-private"] = armnetwork.Interface{
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{
				Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{},
			}},
		},
	}
	vm.Properties.NetworkProfile.NetworkInterfaces[0].ID = ptr(privateNIC)
	ip, err = vmPublicIP(context.Background(), api, vm)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "" {
		t.Fatalf("private nic public ip = %q", ip)
	}
}

func TestAzurePublicIPWithoutAllowIsNotReachable(t *testing.T) {
	c := NewCollector("sub", "eastus")
	nsgID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/deny-all"
	nsg := &armnetwork.SecurityGroup{
		ID:       ptr(nsgID),
		Name:     ptr("deny-all"),
		Location: ptr("eastus"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				nsgRule("deny-internet", 100, armnetwork.SecurityRuleAccessDeny, "*", armnetwork.SecurityRuleProtocolAsterisk, "*"),
			},
		},
	}
	workloadID := c.nodeID("workload", "web")
	var batch graph.Batch
	err := c.attachAzureExposure(&batch, workloadID, []azureNICFacts{{
		PublicIP: "20.1.2.3",
		NicNSGID: nsgID,
	}}, indexSecurityGroups([]*armnetwork.SecurityGroup{nsg}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasEdge(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("public IP behind a deny-all NSG should not be reachable")
	}
	nsgNode := c.nodeID("network", "rg1/deny-all")
	if findNode(batch, nsgNode).ID == "" {
		t.Fatal("NSG should be a network node")
	}
	if !hasEdge(batch, workloadID, nsgNode, graph.EdgeAffects) {
		t.Fatal("NSG should be attached to the workload")
	}
}

func TestAzurePrivateIPBehindLoadBalancerIsReachable(t *testing.T) {
	c := NewCollector("sub", "eastus")
	nsgID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/web"
	ipConfigID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ip1"
	pipID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/lb-ip"
	nsg := &armnetwork.SecurityGroup{
		ID:       ptr(nsgID),
		Name:     ptr("web"),
		Location: ptr("eastus"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				nsgRule("allow-web", 100, armnetwork.SecurityRuleAccessAllow, "Internet", armnetwork.SecurityRuleProtocolTCP, "80"),
			},
			DefaultSecurityRules: []*armnetwork.SecurityRule{
				nsgRule("DenyAllInBound", 65500, armnetwork.SecurityRuleAccessDeny, "*", armnetwork.SecurityRuleProtocolAsterisk, "*"),
			},
		},
	}
	lb := &armnetwork.LoadBalancer{
		Name: ptr("web-lb"),
		Properties: &armnetwork.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: []*armnetwork.FrontendIPConfiguration{{
				Properties: &armnetwork.FrontendIPConfigurationPropertiesFormat{
					PublicIPAddress: &armnetwork.PublicIPAddress{ID: ptr(pipID)},
				},
			}},
			BackendAddressPools: []*armnetwork.BackendAddressPool{{
				Properties: &armnetwork.BackendAddressPoolPropertiesFormat{
					BackendIPConfigurations: []*armnetwork.InterfaceIPConfiguration{{ID: ptr(ipConfigID)}},
				},
			}},
		},
	}
	targets := azurePublicLBTargets([]*armnetwork.LoadBalancer{lb})
	workloadID := c.nodeID("workload", "web")
	var batch graph.Batch
	err := c.attachAzureExposure(&batch, workloadID, []azureNICFacts{{
		NicNSGID:   nsgID,
		IPConfigID: ipConfigID,
	}}, indexSecurityGroups([]*armnetwork.SecurityGroup{nsg}), targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge, ok := edgeByType(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable)
	if !ok {
		t.Fatal("private IP behind a public load balancer and an allow rule should be reachable")
	}
	if edge.Properties["via_nsg"] != "web" || edge.Properties["via_load_balancer"] != "web-lb" {
		t.Fatalf("reachable properties = %#v", edge.Properties)
	}
	if !hasEdge(batch, workloadID, c.nodeID("network", "rg1/web"), graph.EdgeAffects) {
		t.Fatal("NSG should be attached to the workload")
	}

	var closed graph.Batch
	err = c.attachAzureExposure(&closed, workloadID, []azureNICFacts{{
		NicNSGID:   nsgID,
		IPConfigID: ipConfigID,
	}}, indexSecurityGroups([]*armnetwork.SecurityGroup{nsg}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasEdge(closed, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("an allow rule alone should not expose a private IP")
	}
}

func TestAzurePublicIPWithoutNSGStaysReachable(t *testing.T) {
	c := NewCollector("sub", "eastus")
	workloadID := c.nodeID("workload", "web")
	var batch graph.Batch
	err := c.attachAzureExposure(&batch, workloadID, []azureNICFacts{{
		PublicIP: "20.1.2.3",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge, ok := edgeByType(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable)
	if !ok {
		t.Fatal("public IP with no NSG should stay reachable")
	}
	if edge.Properties["via_public_ip"] != "20.1.2.3" {
		t.Fatalf("reachable properties = %#v", edge.Properties)
	}

	var private graph.Batch
	err = c.attachAzureExposure(&private, c.nodeID("workload", "db"), []azureNICFacts{{}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasEdge(private, graph.InternetNodeID, c.nodeID("workload", "db"), graph.EdgeReachable) {
		t.Fatal("private IP with no NSG should not be reachable")
	}
}

func TestAzureSubnetDenyBlocksPublicIP(t *testing.T) {
	c := NewCollector("sub", "eastus")
	nicID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nic-allow"
	subnetID := "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/subnet-deny"
	allow := &armnetwork.SecurityGroup{
		ID:   ptr(nicID),
		Name: ptr("nic-allow"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				nsgRule("allow", 100, armnetwork.SecurityRuleAccessAllow, "Internet", armnetwork.SecurityRuleProtocolTCP, "443"),
			},
		},
	}
	deny := &armnetwork.SecurityGroup{
		ID:   ptr(subnetID),
		Name: ptr("subnet-deny"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				nsgRule("deny", 100, armnetwork.SecurityRuleAccessDeny, "*", armnetwork.SecurityRuleProtocolAsterisk, "*"),
			},
		},
	}
	workloadID := c.nodeID("workload", "web")
	var batch graph.Batch
	err := c.attachAzureExposure(&batch, workloadID, []azureNICFacts{{
		PublicIP:    "20.1.2.3",
		NicNSGID:    nicID,
		SubnetNSGID: subnetID,
	}}, indexSecurityGroups([]*armnetwork.SecurityGroup{allow, deny}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasEdge(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("subnet deny should block a NIC allow")
	}
}

func nsgRule(name string, priority int32, access armnetwork.SecurityRuleAccess, source string, protocol armnetwork.SecurityRuleProtocol, ports string) *armnetwork.SecurityRule {
	return &armnetwork.SecurityRule{
		Name: ptr(name),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                   ptr(access),
			Direction:                ptr(armnetwork.SecurityRuleDirectionInbound),
			Priority:                 ptr(priority),
			Protocol:                 ptr(protocol),
			SourceAddressPrefix:      ptr(source),
			DestinationAddressPrefix: ptr("*"),
			DestinationPortRange:     ptr(ports),
		},
	}
}

func edgeByType(batch graph.Batch, source, target, edgeType string) (graph.Edge, bool) {
	for _, edge := range batch.Edges {
		if edge.SourceID == source && edge.TargetID == target && edge.Type == edgeType {
			return edge, true
		}
	}
	return graph.Edge{}, false
}

func TestAzureBlobPublic(t *testing.T) {
	allow := true
	deny := false
	private := []*armstorage.ListContainerItem{{
		Properties: &armstorage.ContainerProperties{PublicAccess: ptr(armstorage.PublicAccessNone)},
	}}
	if azureBlobPublic(&allow, private) {
		t.Fatal("account that allows public blobs but has only private containers is not public")
	}
	onePublic := append(private, &armstorage.ListContainerItem{
		Properties: &armstorage.ContainerProperties{PublicAccess: ptr(armstorage.PublicAccessBlob)},
	})
	if !azureBlobPublic(&allow, onePublic) {
		t.Fatal("expected a container with anonymous blob read to be public")
	}
	if azureBlobPublic(&deny, onePublic) {
		t.Fatal("account that disallows public blobs is not public")
	}
}

type fakeAzureNetwork struct {
	nics map[string]armnetwork.Interface
	pips map[string]armnetwork.PublicIPAddress
}

func (f fakeAzureNetwork) getNIC(_ context.Context, resourceGroup, name string) (armnetwork.Interface, error) {
	nic, ok := f.nics[resourceGroup+"/"+name]
	if !ok {
		return armnetwork.Interface{}, &azcore.ResponseError{StatusCode: 404}
	}
	return nic, nil
}

func (f fakeAzureNetwork) getPublicIP(_ context.Context, resourceGroup, name string) (armnetwork.PublicIPAddress, error) {
	pip, ok := f.pips[resourceGroup+"/"+name]
	if !ok {
		return armnetwork.PublicIPAddress{}, &azcore.ResponseError{StatusCode: 404}
	}
	return pip, nil
}

func ptr[T any](v T) *T { return &v }
