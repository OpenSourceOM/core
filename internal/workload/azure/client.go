// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/OpenSourceOM/core/internal/workload"
)

// Client snapshots managed OS disks and attaches the copy to the worker.
type Client struct {
	sub   string
	vms   *armcompute.VirtualMachinesClient
	snaps *armcompute.SnapshotsClient
	disks *armcompute.DisksClient
}

var _ API = (*Client)(nil)

// NewClient uses the default Azure credential for the subscription.
func NewClient(subscriptionID string) (*Client, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credentials: %w", err)
	}
	vms, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	snaps, err := armcompute.NewSnapshotsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	disks, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return &Client{sub: subscriptionID, vms: vms, snaps: snaps, disks: disks}, nil
}

func (c *Client) List(ctx context.Context, location string) ([]Machine, error) {
	pager := c.vms.NewListByLocationPager(normalizeLocation(location), nil)
	var out []Machine
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list virtual machines: %w", err)
		}
		for _, vm := range page.Value {
			machine, ok := machineFrom(vm)
			if ok {
				out = append(out, machine)
			}
		}
	}
	return out, nil
}

func (c *Client) CreateSnapshot(ctx context.Context, group, location, sourceDisk, vm string) (string, error) {
	name := objectName(vm)
	poller, err := c.snaps.BeginCreateOrUpdate(ctx, group, name, snapshotBody(location, sourceDisk, vm), nil)
	if err != nil {
		return "", fmt.Errorf("create snapshot: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return name, fmt.Errorf("create snapshot: %w", err)
	}
	return name, nil
}

func (c *Client) DeleteSnapshot(ctx context.Context, group, name string) error {
	poller, err := c.snaps.BeginDelete(ctx, group, name, nil)
	if isAzureNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := poller.PollUntilDone(ctx, nil); isAzureNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) CreateDisk(ctx context.Context, group, location, snapshotName string, zones []string, vm string) (string, error) {
	name := objectName(vm)
	poller, err := c.disks.BeginCreateOrUpdate(ctx, group, name, diskBody(location, c.resourceID(group, "snapshots", snapshotName), zones, vm), nil)
	if err != nil {
		return "", fmt.Errorf("create disk: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return name, fmt.Errorf("create disk: %w", err)
	}
	return name, nil
}

func (c *Client) DeleteDisk(ctx context.Context, group, name string) error {
	poller, err := c.disks.BeginDelete(ctx, group, name, nil)
	if isAzureNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := poller.PollUntilDone(ctx, nil); isAzureNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) Attach(ctx context.Context, group, vm, diskName string, lun int32) error {
	poller, err := c.vms.BeginAttachDetachDataDisks(ctx, group, vm, armcompute.AttachDetachDataDisksRequest{
		DataDisksToAttach: []*armcompute.DataDisksToAttach{{
			DiskID:       ptr(c.resourceID(group, "disks", diskName)),
			Lun:          ptr(lun),
			DeleteOption: ptr(armcompute.DiskDeleteOptionTypesDetach),
		}},
	}, nil)
	if err != nil {
		return fmt.Errorf("attach disk: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("attach disk: %w", err)
	}
	return nil
}

func (c *Client) Detach(ctx context.Context, group, vm, diskName string) error {
	poller, err := c.vms.BeginAttachDetachDataDisks(ctx, group, vm, armcompute.AttachDetachDataDisksRequest{
		DataDisksToDetach: []*armcompute.DataDisksToDetach{{
			DiskID: ptr(c.resourceID(group, "disks", diskName)),
		}},
	}, nil)
	if isAzureNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if isAzureNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) resourceID(group, kind, name string) string {
	return "/subscriptions/" + c.sub + "/resourceGroups/" + group + "/providers/Microsoft.Compute/" + kind + "/" + name
}

func snapshotBody(location, sourceDisk, vm string) armcompute.Snapshot {
	return armcompute.Snapshot{
		Location: ptr(location),
		Tags:     scanTags(vm),
		Properties: &armcompute.SnapshotProperties{
			Incremental:         ptr(false),
			NetworkAccessPolicy: ptr(armcompute.NetworkAccessPolicyDenyAll),
			PublicNetworkAccess: ptr(armcompute.PublicNetworkAccessDisabled),
			CreationData: &armcompute.CreationData{
				CreateOption:     ptr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: ptr(sourceDisk),
			},
		},
	}
}

func diskBody(location, snapshotID string, zones []string, vm string) armcompute.Disk {
	disk := armcompute.Disk{
		Location: ptr(location),
		Tags:     scanTags(vm),
		Properties: &armcompute.DiskProperties{
			NetworkAccessPolicy: ptr(armcompute.NetworkAccessPolicyDenyAll),
			PublicNetworkAccess: ptr(armcompute.PublicNetworkAccessDisabled),
			CreationData: &armcompute.CreationData{
				CreateOption:     ptr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: ptr(snapshotID),
			},
		},
	}
	if len(zones) > 0 {
		disk.Zones = make([]*string, len(zones))
		for i, zone := range zones {
			disk.Zones[i] = ptr(zone)
		}
	}
	return disk
}

func scanTags(vm string) map[string]*string {
	return map[string]*string{
		"opensourceom:scan":     ptr("workload"),
		"opensourceom:instance": ptr(vm),
	}
}

func machineFrom(vm *armcompute.VirtualMachine) (Machine, bool) {
	if vm == nil || vm.Name == nil || vm.ID == nil {
		return Machine{}, false
	}
	group, _ := resourceParts(*vm.ID)
	if group == "" {
		return Machine{}, false
	}
	machine := Machine{
		Name:          *vm.Name,
		ResourceGroup: group,
		Location:      normalizeLocation(value(vm.Location)),
		ID:            *vm.ID,
	}
	if vm.Properties == nil || vm.Properties.StorageProfile == nil {
		if vm.Properties != nil {
			machine.ProvisioningState = value(vm.Properties.ProvisioningState)
		}
		return machine, true
	}
	machine.ProvisioningState = value(vm.Properties.ProvisioningState)
	profile := vm.Properties.StorageProfile
	if profile.OSDisk != nil {
		if profile.OSDisk.OSType != nil {
			machine.OS = strings.ToLower(string(*profile.OSDisk.OSType))
		}
		machine.Ephemeral = profile.OSDisk.DiffDiskSettings != nil
		if profile.OSDisk.ManagedDisk != nil {
			machine.OSDiskID = value(profile.OSDisk.ManagedDisk.ID)
		}
	}
	for _, disk := range profile.DataDisks {
		if disk != nil && disk.Lun != nil {
			machine.DataLUNs = append(machine.DataLUNs, *disk.Lun)
		}
	}
	return machine, true
}

func resourceParts(id string) (group, name string) {
	parts := strings.Split(id, "/")
	for i := 0; i < len(parts)-1; i++ {
		switch strings.ToLower(parts[i]) {
		case "resourcegroups":
			group = parts[i+1]
		case "disks", "snapshots", "virtualmachines":
			name = parts[i+1]
		}
	}
	return group, name
}

func objectName(vm string) string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return workload.SanitizeName(vm, strconv.FormatInt(time.Now().Unix(), 16), 63)
	}
	return workload.SanitizeName(vm, hex.EncodeToString(buf), 63)
}

func isAzureNotFound(err error) bool {
	var resp *azcore.ResponseError
	return errors.As(err, &resp) && resp.StatusCode == http.StatusNotFound
}

func value(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func ptr[T any](v T) *T { return &v }
