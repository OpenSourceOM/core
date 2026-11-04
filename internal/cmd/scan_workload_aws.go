// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"time"

	awscol "github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/workload"
	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
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
	return `Inventory packages on Linux root volumes in a production AWS account.

Run it as root on an EC2 instance in the scanner account, in the same region. Pass --snapshot-role and --external-id for the role deploy/connect/aws creates in the production account. The command assumes that role, snapshots each root volume, and shares the snapshot with the scanner account. The worker copies it, creates a volume in this instance's availability zone, attaches it, and mounts it read-only. It writes CPE 2.3 names and package URLs onto the workload node from om scan aws, then deletes the copy and the source snapshot, including when a read fails. File contents stay off the graph.

An encrypted volume needs --kms-key, a key in the scanner account. The production key policy has to allow the scanner role to decrypt. om scan aws stays a read-only API scan. A later om scan aws keeps packages already stored on the workload. Snapshots and volumes are tagged opensourceom:scan=workload, which is how to find one left behind by a killed process.

This command reads Linux root volumes. Windows instances are skipped. LVM and disks other than the root volume are skipped. Boot images are "om scan workload image aws". Container layers, function bundles, and shared filesystems are later scans.

` + granted("Production role", awsv.Permissions) + "\n\n" + granted("Scanner role", awsv.WorkerPermissions)
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

	localCfg, prodCfg, scannerAccount, prodAccount, err := loadScannerAWS(ctx, cfg.AWSRegion)
	if err != nil {
		return err
	}

	scanner := &awsv.Scanner{
		API:       ec2.NewFromConfig(localCfg),
		Prod:      ec2.NewFromConfig(prodCfg),
		AccountID: scannerAccount,
		KMSKeyID:  scannerKMSKey(),
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
		nodeID := awscol.WorkloadNodeID(prodAccount, cfg.AWSRegion, res.InstanceID)
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
	scanWorkloadAWSCmd.Flags().StringVar(&awsSnapshotRole, "snapshot-role", "", "production role ARN from deploy/connect/aws (or OM_SNAPSHOT_ROLE_ARN)")
	scanWorkloadAWSCmd.Flags().StringVar(&awsExternalID, "external-id", "", "external id the production role trusts (or OM_EXTERNAL_ID)")
	scanWorkloadAWSCmd.Flags().StringVar(&awsKMSKey, "kms-key", "", "scanner account KMS key id or ARN for the copied snapshot (or OM_SCANNER_KMS_KEY_ID)")
	scanWorkloadCmd.AddCommand(scanWorkloadAWSCmd)
}
