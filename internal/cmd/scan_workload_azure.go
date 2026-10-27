// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	azurecol "github.com/OpenSourceOM/core/internal/collectors/azure"
	"github.com/OpenSourceOM/core/internal/workload"
	azurev "github.com/OpenSourceOM/core/internal/workload/azure"
	"github.com/spf13/cobra"
)

var (
	azureWorkloadTimeout time.Duration
	azureWorkloadVMs     []string
)

var scanWorkloadAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Inventory packages on Azure Linux OS disks",
	Long:  workloadAzureLong(),
	RunE:  runScanWorkloadAzure,
}

func workloadAzureLong() string {
	return `Inventory packages on Linux OS disks in the current Azure subscription.

Run it as root on an Azure VM in that subscription. The command snapshots each managed OS disk in this VM's region, creates a disk from the snapshot in this VM's zone, attaches it, and mounts it read-only. It writes CPE 2.3 names and package URLs onto the workload node from om scan azure, then deletes the snapshot and the disk, including when a read fails. File contents stay on the disk.

om scan azure stays a read-only API scan. A later om scan azure keeps packages already stored on the workload. Snapshots and disks are tagged opensourceom:scan=workload, which is how to find one left behind by a killed process. The copies are created in this VM's resource group and cannot be exported.

This command reads Linux OS disks. Windows VMs are skipped. Ephemeral OS disks, unmanaged VHDs, LVM, and data disks are skipped. VMs in another region are skipped; run the command on a VM in that region. Boot images are "om scan workload image azure".

The graph id matches om scan azure: azure:<AZURE_SUBSCRIPTION_ID>:<AZURE_LOCATION>:workload:<vm name>.

Azure RBAC actions:
  ` + strings.Join(azurev.Permissions, "\n  ")
}

func runScanWorkloadAzure(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	if cfg.AzureSubscriptionID == "" {
		return fmt.Errorf("AZURE_SUBSCRIPTION_ID is required")
	}
	ctx := cmd.Context()
	worker, err := azurev.LookupWorker(ctx)
	if err != nil {
		return err
	}
	if err := azurev.CheckSubscription(worker.SubscriptionID, cfg.AzureSubscriptionID); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("om scan workload azure mounts the snapshot and must run as root on the worker")
	}

	store, err := openGraphStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	client, err := azurev.NewClient(cfg.AzureSubscriptionID)
	if err != nil {
		return err
	}
	scanner := &azurev.Scanner{
		API: client,
		Worker: azurev.Worker{
			Name:           worker.Name,
			ResourceGroup:  worker.ResourceGroup,
			SubscriptionID: worker.SubscriptionID,
			Location:       worker.Location,
			Zone:           worker.Zone,
		},
		Only:    azureWorkloadVMs,
		Timeout: azureWorkloadTimeout,
		Mount:   azurev.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(name, group string) {
			fmt.Printf("%s: snapshotting the OS disk\n", group+"/"+name)
		},
	}
	wrote := 0
	err = scanner.Scan(ctx, func(res azurev.Result) error {
		label := groupLabel(res.ResourceGroup, res.Name)
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		nodeID := azurecol.WorkloadNodeID(cfg.AzureSubscriptionID, cfg.AzureLocation, res.Name)
		if err := store.SetWorkloadPackages(ctx, nodeID, res.Packages); err != nil {
			return err
		}
		fmt.Printf("%s: %d package identifiers\n", label, len(res.Packages))
		wrote++
		return nil
	})
	fmt.Printf("Stored packages on %d workloads.\n", wrote)
	return err
}

func groupLabel(group, name string) string {
	if group == "" {
		return name
	}
	return group + "/" + name
}

func init() {
	scanWorkloadAzureCmd.Flags().DurationVar(&azureWorkloadTimeout, "timeout", 30*time.Minute, "time limit for each virtual machine")
	scanWorkloadAzureCmd.Flags().StringArrayVar(&azureWorkloadVMs, "instance", nil, "VM name, resource group/name, or resource id (repeat to scan several; the default is every VM in this region)")
	scanWorkloadCmd.AddCommand(scanWorkloadAzureCmd)
}
