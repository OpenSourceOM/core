// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

type azureNetworkAPI interface {
	getNIC(ctx context.Context, resourceGroup, name string) (armnetwork.Interface, error)
	getPublicIP(ctx context.Context, resourceGroup, name string) (armnetwork.PublicIPAddress, error)
}

type armNetworkAPI struct {
	nics *armnetwork.InterfacesClient
	pips *armnetwork.PublicIPAddressesClient
}

func (a armNetworkAPI) getNIC(ctx context.Context, resourceGroup, name string) (armnetwork.Interface, error) {
	resp, err := a.nics.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return armnetwork.Interface{}, err
	}
	return resp.Interface, nil
}

func (a armNetworkAPI) getPublicIP(ctx context.Context, resourceGroup, name string) (armnetwork.PublicIPAddress, error) {
	resp, err := a.pips.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return armnetwork.PublicIPAddress{}, err
	}
	return resp.PublicIPAddress, nil
}

func vmPublicIP(ctx context.Context, api azureNetworkAPI, vm *armcompute.VirtualMachine) (string, error) {
	if vm == nil || vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return "", nil
	}
	for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if nicRef == nil || nicRef.ID == nil || *nicRef.ID == "" {
			continue
		}
		resourceGroup, name, ok := azureResourceParts(*nicRef.ID)
		if !ok {
			return "", fmt.Errorf("network interface id %s: missing resource group or name", *nicRef.ID)
		}
		nic, err := api.getNIC(ctx, resourceGroup, name)
		if err != nil {
			if azureNotFound(err) {
				continue
			}
			return "", fmt.Errorf("get network interface %s: %w", name, err)
		}
		ip, err := publicIPFromNIC(ctx, api, nic)
		if err != nil {
			return "", err
		}
		if ip != "" {
			return ip, nil
		}
	}
	return "", nil
}

func publicIPFromNIC(ctx context.Context, api azureNetworkAPI, nic armnetwork.Interface) (string, error) {
	if nic.Properties == nil {
		return "", nil
	}
	for _, cfg := range nic.Properties.IPConfigurations {
		if cfg == nil || cfg.Properties == nil || cfg.Properties.PublicIPAddress == nil {
			continue
		}
		pip := cfg.Properties.PublicIPAddress
		if pip.Properties != nil && pip.Properties.IPAddress != nil && *pip.Properties.IPAddress != "" {
			return *pip.Properties.IPAddress, nil
		}
		if pip.ID == nil || *pip.ID == "" {
			continue
		}
		resourceGroup, name, ok := azureResourceParts(*pip.ID)
		if !ok {
			return "", fmt.Errorf("public ip id %s: missing resource group or name", *pip.ID)
		}
		addr, err := api.getPublicIP(ctx, resourceGroup, name)
		if err != nil {
			if azureNotFound(err) {
				continue
			}
			return "", fmt.Errorf("get public ip %s: %w", name, err)
		}
		if addr.Properties != nil && addr.Properties.IPAddress != nil && *addr.Properties.IPAddress != "" {
			return *addr.Properties.IPAddress, nil
		}
	}
	return "", nil
}

func (c *Collector) addInternetEdge(batch *graph.Batch, workloadID, publicIP string) {
	if publicIP == "" {
		return
	}
	batch.Edges = append(batch.Edges, graph.Edge{
		ID:       c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
		SourceID: graph.InternetNodeID,
		TargetID: workloadID,
		Type:     graph.EdgeReachable,
	})
}

func azureBlobPublic(allow *bool, containers []*armstorage.ListContainerItem) bool {
	if allow != nil && !*allow {
		return false
	}
	for _, item := range containers {
		if item == nil || item.Properties == nil || item.Properties.PublicAccess == nil {
			continue
		}
		switch *item.Properties.PublicAccess {
		case armstorage.PublicAccessBlob, armstorage.PublicAccessContainer:
			return true
		}
	}
	return false
}

func azureResourceGroup(id string) (string, bool) {
	group, _, ok := azureResourceParts(id)
	return group, ok
}

func azureResourceParts(id string) (resourceGroup, name string, ok bool) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	var group string
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			group = parts[i+1]
		}
	}
	if group == "" || len(parts) == 0 {
		return "", "", false
	}
	name = parts[len(parts)-1]
	if name == "" {
		return "", "", false
	}
	return group, name, true
}

func azureNotFound(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}
