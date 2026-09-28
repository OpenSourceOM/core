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

func TestVMReachableOnlyWithPublicIP(t *testing.T) {
	c := NewCollector("sub", "eastus")
	var batch graph.Batch
	c.addInternetEdge(&batch, c.nodeID("workload", "private"), "")
	c.addInternetEdge(&batch, c.nodeID("workload", "web"), "20.1.2.3")
	if len(batch.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(batch.Edges))
	}
	if batch.Edges[0].Type != graph.EdgeReachable || batch.Edges[0].SourceID != graph.InternetNodeID {
		t.Fatalf("edge = %+v", batch.Edges[0])
	}
	if batch.Edges[0].TargetID != c.nodeID("workload", "web") {
		t.Fatalf("reachable target = %s", batch.Edges[0].TargetID)
	}
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
