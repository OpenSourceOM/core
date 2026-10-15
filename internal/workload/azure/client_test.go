// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
)

func TestSnapshotBodyDoesNotExportOrSetAKey(t *testing.T) {
	body := snapshotBody("eastus", "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/disks/os", "web")
	if body.Properties == nil || body.Properties.CreationData == nil {
		t.Fatal("missing creation data")
	}
	if body.Properties.CreationData.CreateOption == nil || *body.Properties.CreationData.CreateOption != armcompute.DiskCreateOptionCopy {
		t.Fatalf("create option = %v", body.Properties.CreationData.CreateOption)
	}
	if body.Properties.CreationData.SourceResourceID == nil || *body.Properties.CreationData.SourceResourceID != "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/disks/os" {
		t.Fatalf("source = %v", body.Properties.CreationData.SourceResourceID)
	}
	if body.Properties.Incremental == nil || *body.Properties.Incremental {
		t.Fatal("snapshot is incremental")
	}
	if body.Properties.NetworkAccessPolicy == nil || *body.Properties.NetworkAccessPolicy != armcompute.NetworkAccessPolicyDenyAll {
		t.Fatal("snapshot can be exported")
	}
	if body.Properties.Encryption != nil {
		t.Fatal("snapshot sets its own encryption key")
	}
	if body.Tags["opensourceom:scan"] == nil || *body.Tags["opensourceom:scan"] != "workload" {
		t.Fatalf("tags = %#v", body.Tags)
	}
}

func TestDiskBodyUsesWorkerZone(t *testing.T) {
	body := diskBody("eastus", "/subscriptions/sub/resourceGroups/scan/providers/Microsoft.Compute/snapshots/snap", []string{"1"}, "web")
	if len(body.Zones) != 1 || body.Zones[0] == nil || *body.Zones[0] != "1" {
		t.Fatalf("zones = %#v", body.Zones)
	}
	if body.Properties.Encryption != nil {
		t.Fatal("disk sets its own encryption key")
	}
}

func TestMachineFromOSDisk(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/App/providers/Microsoft.Compute/virtualMachines/web"
	disk := "/subscriptions/sub/resourceGroups/App/providers/Microsoft.Compute/disks/os"
	vm := &armcompute.VirtualMachine{
		Name:     ptr("web"),
		ID:       ptr(id),
		Location: ptr("East US"),
		Properties: &armcompute.VirtualMachineProperties{
			ProvisioningState: ptr("Succeeded"),
			StorageProfile: &armcompute.StorageProfile{
				OSDisk: &armcompute.OSDisk{
					OSType:      ptr(armcompute.OperatingSystemTypesLinux),
					ManagedDisk: &armcompute.ManagedDiskParameters{ID: ptr(disk)},
				},
				DataDisks: []*armcompute.DataDisk{{Lun: ptr(int32(3))}},
			},
		},
	}
	got, ok := machineFrom(vm)
	if !ok {
		t.Fatal("machine was dropped")
	}
	if got.ResourceGroup != "App" || got.Location != "eastus" || got.OS != "linux" || got.OSDiskID != disk || len(got.DataLUNs) != 1 || got.DataLUNs[0] != 3 {
		t.Fatalf("machine = %#v", got)
	}

	vm.Properties.StorageProfile.OSDisk.OSType = ptr(armcompute.OperatingSystemTypesWindows)
	vm.Properties.StorageProfile.OSDisk.DiffDiskSettings = &armcompute.DiffDiskSettings{}
	vm.Properties.StorageProfile.OSDisk.ManagedDisk = nil
	got, _ = machineFrom(vm)
	if got.OS != "windows" || !got.Ephemeral || got.OSDiskID != "" {
		t.Fatalf("machine = %#v", got)
	}
}

func TestParseMetadata(t *testing.T) {
	body := []byte(`{"compute":{"name":"worker","resourceGroupName":"scan","subscriptionId":"sub","location":"East US","zone":"1"}}`)
	got, err := parseMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "worker" || got.ResourceGroup != "scan" || got.Location != "eastus" || got.Zone != "1" || got.SubscriptionID != "sub" {
		t.Fatalf("worker = %#v", got)
	}
}

func TestCheckSubscription(t *testing.T) {
	if err := CheckSubscription("sub", "SUB"); err != nil {
		t.Fatal(err)
	}
	err := CheckSubscription("other", "sub")
	if err == nil || err.Error() != "this VM is in subscription other; set AZURE_SUBSCRIPTION_ID=other" {
		t.Fatalf("err = %v", err)
	}
}

func TestLUNPaths(t *testing.T) {
	got := lunPaths("2")
	if len(got) != 2 || got[0] != "/dev/disk/azure/scsi1/lun2" || got[1] != "/dev/disk/azure/data/by-lun/lun2" {
		t.Fatalf("paths = %#v", got)
	}
}
