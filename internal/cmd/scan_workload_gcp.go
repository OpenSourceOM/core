// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	gcpcol "github.com/OpenSourceOM/core/internal/collectors/gcp"
	"github.com/OpenSourceOM/core/internal/workload"
	gcpv "github.com/OpenSourceOM/core/internal/workload/gcp"
	"github.com/spf13/cobra"
)

var (
	gcpWorkloadTimeout   time.Duration
	gcpWorkloadInstances []string
)

var scanWorkloadGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Inventory packages on GCE Linux boot disks",
	Long:  workloadGCPLong(),
	RunE:  runScanWorkloadGCP,
}

func workloadGCPLong() string {
	return `Inventory packages on Linux boot disks in the current GCP project.

Run it as root on a GCE instance in that project. The command snapshots each persistent boot disk in this instance's region, creates a disk from the snapshot in this instance's zone, attaches it read-only, and mounts it read-only. It writes CPE 2.3 names and package URLs onto the workload node from om scan gcp, then deletes the snapshot and the disk, including when a read fails. File contents stay on the disk.

om scan gcp stays a read-only API scan. A later om scan gcp keeps packages already stored on the workload. Snapshots and disks are labeled opensourceom-scan=workload, which is how to find one left behind by a killed process. Label keys cannot contain a colon.

This command reads Linux boot disks. Windows instances are skipped. Local SSD boot disks, customer-supplied encryption keys, LVM, and extra disks are skipped. Instances in another region are skipped; run the command on an instance in that region.

The graph id matches om scan gcp: gcp:<GCP_PROJECT_ID>:<zone>:workload:<instance name>.

IAM permissions:
  ` + strings.Join(gcpv.Permissions, "\n  ")
}

func runScanWorkloadGCP(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	if cfg.GCPProjectID == "" {
		return fmt.Errorf("GCP_PROJECT_ID is required")
	}
	ctx := cmd.Context()
	worker, err := gcpv.LookupWorker(ctx)
	if err != nil {
		return err
	}
	if err := gcpv.CheckProject(worker.ProjectID, cfg.GCPProjectID); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("om scan workload gcp mounts the snapshot and must run as root on the worker")
	}

	store, err := openGraphStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	client, err := gcpv.NewClient(ctx, cfg.GCPProjectID)
	if err != nil {
		return err
	}
	scanner := &gcpv.Scanner{
		API: client,
		Worker: gcpv.Worker{
			Name:      worker.Name,
			ProjectID: worker.ProjectID,
			Zone:      worker.Zone,
		},
		Only:    gcpWorkloadInstances,
		Timeout: gcpWorkloadTimeout,
		Mount:   gcpv.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(name, zone string) {
			fmt.Printf("%s: snapshotting the boot disk\n", zone+"/"+name)
		},
	}
	wrote := 0
	err = scanner.Scan(ctx, func(res gcpv.Result) error {
		label := zoneLabel(res.Zone, res.Name)
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		nodeID := gcpcol.WorkloadNodeID(cfg.GCPProjectID, res.Zone, res.Name)
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

func zoneLabel(zone, name string) string {
	if zone == "" {
		return name
	}
	return zone + "/" + name
}

func init() {
	scanWorkloadGCPCmd.Flags().DurationVar(&gcpWorkloadTimeout, "timeout", 30*time.Minute, "time limit for each instance")
	scanWorkloadGCPCmd.Flags().StringArrayVar(&gcpWorkloadInstances, "instance", nil, "instance name or zone/name (repeat to scan several; the default is every instance in this region)")
	scanWorkloadCmd.AddCommand(scanWorkloadGCPCmd)
}
