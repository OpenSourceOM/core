// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	awscol "github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/workload"
	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
)

var (
	awsWorkloadTimeout   time.Duration
	awsWorkloadInstances []string
)

var scanWorkloadAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Inventory packages on AWS Linux root volumes",
	Long:  workloadAWSLong(),
	RunE:  runScanWorkloadAWS,
}

func workloadAWSLong() string {
	return `Inventory packages on Linux root volumes in the current AWS account.

Run it as root on an EC2 instance in that account. The command snapshots each root volume, creates a volume from the snapshot in this instance's availability zone, attaches it, and mounts it read-only. It writes CPE 2.3 names and package URLs onto the workload node from om scan aws, then deletes the snapshot and the volume, including when a read fails. File contents stay on the volume.

om scan aws stays a read-only API scan. A later om scan aws keeps packages already stored on the workload. Snapshots and volumes are tagged opensourceom:scan=workload, which is how to find one left behind by a killed process.

This command reads Linux root volumes. Windows instances are skipped. LVM and disks other than the root volume are skipped. Boot images are "om scan workload image aws". Container layers, function bundles, and shared filesystems are later scans.

IAM actions:
  ` + strings.Join(awsv.Permissions, "\n  ")
}

func runScanWorkloadAWS(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	ctx := cmd.Context()
	worker, err := awsv.LookupWorker(ctx)
	if err != nil {
		return err
	}
	if err := awsv.CheckRegion(worker.Region, cfg.AWSRegion); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("om scan workload aws mounts the snapshot and must run as root on the worker")
	}

	store, err := openGraphStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	collector, err := awscol.NewCollector(ctx, cfg.AWSRegion)
	if err != nil {
		return err
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	scanner := &awsv.Scanner{
		API: ec2.NewFromConfig(awsCfg),
		Worker: awsv.Worker{
			InstanceID:       worker.InstanceID,
			AvailabilityZone: worker.AvailabilityZone,
			Region:           worker.Region,
		},
		Only:    awsWorkloadInstances,
		Timeout: awsWorkloadTimeout,
		Mount:   awsv.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(instanceID, name string) {
			fmt.Printf("%s: snapshotting the root volume\n", workloadLabel(instanceID, name))
		},
	}
	wrote := 0
	err = scanner.Scan(ctx, func(res awsv.Result) error {
		label := workloadLabel(res.InstanceID, res.Name)
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		nodeID := awscol.WorkloadNodeID(collector.AccountID, cfg.AWSRegion, res.InstanceID)
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

func workloadLabel(instanceID, name string) string {
	if name != "" && name != instanceID {
		return instanceID + " (" + name + ")"
	}
	return instanceID
}

func init() {
	scanWorkloadAWSCmd.Flags().DurationVar(&awsWorkloadTimeout, "timeout", 30*time.Minute, "time limit for each instance")
	scanWorkloadAWSCmd.Flags().StringArrayVar(&awsWorkloadInstances, "instance", nil, "EC2 instance to scan (repeat to scan several; the default is every instance in the region)")
	scanWorkloadCmd.AddCommand(scanWorkloadAWSCmd)
}
