// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	awscol "github.com/OpenSourceOM/core/internal/collectors/aws"
	azurecol "github.com/OpenSourceOM/core/internal/collectors/azure"
	gcpcol "github.com/OpenSourceOM/core/internal/collectors/gcp"
	"github.com/OpenSourceOM/core/internal/workload"
	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
	azurev "github.com/OpenSourceOM/core/internal/workload/azure"
	gcpv "github.com/OpenSourceOM/core/internal/workload/gcp"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
)

var (
	awsImageTimeout   time.Duration
	awsImageIDs       []string
	azureImageTimeout time.Duration
	azureImageIDs     []string
	gcpImageTimeout   time.Duration
	gcpImageIDs       []string
)

var scanWorkloadImageCmd = &cobra.Command{
	Use:   "image",
	Short: "Inventory packages on boot images",
	Long: `Inventory packages on boot images in the current account.

Each cloud is its own command: "om scan workload image aws", "om scan workload image azure", and "om scan workload image gcp". Each reads a boot image once and writes those package identifiers onto instances launched from it. om scan aws, om scan azure, and om scan gcp stay read-only.`,
}

var scanWorkloadImageAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Inventory packages on AWS AMIs",
	Long:  workloadImageAWSLong(),
	RunE:  runScanWorkloadImageAWS,
}

var scanWorkloadImageAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Inventory packages on Azure boot images",
	Long:  workloadImageAzureLong(),
	RunE:  runScanWorkloadImageAzure,
}

var scanWorkloadImageGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Inventory packages on GCE boot images",
	Long:  workloadImageGCPLong(),
	RunE:  runScanWorkloadImageGCP,
}

func workloadImageAWSLong() string {
	return `Inventory packages on boot images in the current AWS account.

Run it as root on an EC2 instance in that account. The command reads each AMI once: images this account owns, including ones no instance is running, and images that instances in this region were launched from. It creates a volume from the AMI root snapshot in this instance's availability zone, attaches it, and mounts it read-only. It adds those CPE 2.3 names and package URLs to packages on every workload launched from that AMI, then deletes the volume, including when a read fails. The AMI snapshot is left in place. File contents stay on the volume.

A package that exists only on an instance disk stays on that instance. This command does not copy it onto the image or onto another instance. om scan workload aws, which reads the instance disk, replaces packages with what is installed there. om scan aws stays a read-only API scan and keeps packages already stored. Volumes are tagged opensourceom:scan=workload.

Windows images and instance-store images are skipped. Marketplace images this account cannot snapshot are skipped, and the command says so. Run om scan aws first so the instance nodes exist.

IAM actions:
  ` + strings.Join(awsv.ImagePermissions, "\n  ")
}

func workloadImageAzureLong() string {
	return `Inventory packages on boot images in the current Azure subscription.

Run it as root on an Azure VM in that subscription. The command reads each managed image in this VM's region once, including images no VM is running, and each image a VM in this region was launched from. It creates a disk from the image in this VM's resource group and zone, attaches it, and mounts it read-only. It adds those CPE 2.3 names and package URLs to packages on every workload launched from that image, then deletes the disk, including when a read fails. The image is left in place. File contents stay on the disk.

A package that exists only on a VM disk stays on that VM. This command does not copy it onto the image or onto another VM. om scan workload azure replaces packages with what is installed on that OS disk. om scan azure stays a read-only API scan and keeps packages already stored. Disks are tagged opensourceom:scan=workload and cannot be exported.

Windows images are skipped. Marketplace images this subscription cannot snapshot are skipped, and the command says so. Run om scan azure first so the VM nodes exist.

The graph id matches om scan azure: azure:<AZURE_SUBSCRIPTION_ID>:<AZURE_LOCATION>:workload:<vm name>.

Azure RBAC actions:
  ` + strings.Join(azurev.ImagePermissions, "\n  ")
}

func workloadImageGCPLong() string {
	return `Inventory packages on boot images in the current GCP project.

Run it as root on a GCE instance in that project. The command reads each project image once, including images no instance in this region is running, and each image an instance in this region was launched from. It creates a disk from the image in this instance's zone, attaches it read-only, and mounts it read-only. It adds those CPE 2.3 names and package URLs to packages on every workload launched from that image, then deletes the disk, including when a read fails. The image is left in place. File contents stay on the disk.

A package that exists only on an instance disk stays on that instance. This command does not copy it onto the image or onto another instance. om scan workload gcp replaces packages with what is installed on that boot disk. om scan gcp stays a read-only API scan and keeps packages already stored. Disks are labeled opensourceom-scan=workload. Label keys cannot contain a colon.

Windows images are skipped. Marketplace images this project cannot snapshot are skipped, and the command says so. Run om scan gcp first so the instance nodes exist.

The graph id matches om scan gcp: gcp:<GCP_PROJECT_ID>:<zone>:workload:<instance name>.

IAM permissions:
  ` + strings.Join(gcpv.ImagePermissions, "\n  ")
}

func runScanWorkloadImageAWS(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("om scan workload image aws mounts the image and must run as root on the worker")
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
		Timeout: awsImageTimeout,
		Mount:   awsv.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(imageID, name string) {
			fmt.Printf("%s: reading the boot image\n", workloadLabel(imageID, name))
		},
	}
	wrote := 0
	err = scanner.ScanImages(ctx, awsImageIDs, func(res awsv.ImageResult) error {
		label := workloadLabel(res.ImageID, res.Name)
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		if len(res.Instances) == 0 {
			fmt.Printf("%s: %d package identifiers, no instances launched from this image\n", label, len(res.Packages))
			return nil
		}
		var failed []error
		for _, inst := range res.Instances {
			nodeID := awscol.WorkloadNodeID(collector.AccountID, cfg.AWSRegion, inst.ID)
			if err := store.MergeWorkloadPackages(ctx, nodeID, res.Packages); err != nil {
				failed = append(failed, err)
				continue
			}
			fmt.Printf("%s: %d package identifiers\n", workloadLabel(inst.ID, inst.Name), len(res.Packages))
			wrote++
		}
		return errors.Join(failed...)
	})
	fmt.Printf("Stored packages on %d workloads.\n", wrote)
	return err
}

func runScanWorkloadImageAzure(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("om scan workload image azure mounts the image and must run as root on the worker")
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
	scanner := &azurev.ImageScanner{
		API: client,
		Worker: azurev.Worker{
			Name:           worker.Name,
			ResourceGroup:  worker.ResourceGroup,
			SubscriptionID: worker.SubscriptionID,
			Location:       worker.Location,
			Zone:           worker.Zone,
		},
		Only:    azureImageIDs,
		Timeout: azureImageTimeout,
		Mount:   azurev.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(_, name string) {
			fmt.Printf("%s: reading the boot image\n", name)
		},
	}
	wrote := 0
	err = scanner.Scan(ctx, func(res azurev.ImageResult) error {
		label := res.Name
		if label == "" {
			label = res.ID
		}
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		if len(res.Instances) == 0 {
			fmt.Printf("%s: %d package identifiers, no instances launched from this image\n", label, len(res.Packages))
			return nil
		}
		var failed []error
		for _, vm := range res.Instances {
			nodeID := azurecol.WorkloadNodeID(cfg.AzureSubscriptionID, cfg.AzureLocation, vm.Name)
			if err := store.MergeWorkloadPackages(ctx, nodeID, res.Packages); err != nil {
				failed = append(failed, err)
				continue
			}
			fmt.Printf("%s: %d package identifiers\n", groupLabel(vm.ResourceGroup, vm.Name), len(res.Packages))
			wrote++
		}
		return errors.Join(failed...)
	})
	fmt.Printf("Stored packages on %d workloads.\n", wrote)
	return err
}

func runScanWorkloadImageGCP(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("om scan workload image gcp mounts the image and must run as root on the worker")
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
	scanner := &gcpv.ImageScanner{
		API: client,
		Worker: gcpv.Worker{
			Name:      worker.Name,
			ProjectID: worker.ProjectID,
			Zone:      worker.Zone,
		},
		Only:    gcpImageIDs,
		Timeout: gcpImageTimeout,
		Mount:   gcpv.NewGuest().MountReadOnly,
		Walk:    workload.Walk,
		OnStart: func(_, name string) {
			fmt.Printf("%s: reading the boot image\n", name)
		},
	}
	wrote := 0
	err = scanner.Scan(ctx, func(res gcpv.ImageResult) error {
		label := res.Name
		if label == "" {
			label = res.Link
		}
		if res.Skipped != "" {
			fmt.Printf("%s: skipped (%s)\n", label, res.Skipped)
			return nil
		}
		if len(res.Instances) == 0 {
			fmt.Printf("%s: %d package identifiers, no instances launched from this image\n", label, len(res.Packages))
			return nil
		}
		var failed []error
		for _, inst := range res.Instances {
			nodeID := gcpcol.WorkloadNodeID(cfg.GCPProjectID, inst.Zone, inst.Name)
			if err := store.MergeWorkloadPackages(ctx, nodeID, res.Packages); err != nil {
				failed = append(failed, err)
				continue
			}
			fmt.Printf("%s: %d package identifiers\n", zoneLabel(inst.Zone, inst.Name), len(res.Packages))
			wrote++
		}
		return errors.Join(failed...)
	})
	fmt.Printf("Stored packages on %d workloads.\n", wrote)
	return err
}

func init() {
	scanWorkloadImageAWSCmd.Flags().DurationVar(&awsImageTimeout, "timeout", 30*time.Minute, "time limit for each image")
	scanWorkloadImageAWSCmd.Flags().StringArrayVar(&awsImageIDs, "image", nil, "AMI id or name (repeat to scan several; the default is every owned image and every image an instance in this region uses)")
	scanWorkloadImageAzureCmd.Flags().DurationVar(&azureImageTimeout, "timeout", 30*time.Minute, "time limit for each image")
	scanWorkloadImageAzureCmd.Flags().StringArrayVar(&azureImageIDs, "image", nil, "image name or resource id (repeat to scan several; the default is every image in this region)")
	scanWorkloadImageGCPCmd.Flags().DurationVar(&gcpImageTimeout, "timeout", 30*time.Minute, "time limit for each image")
	scanWorkloadImageGCPCmd.Flags().StringArrayVar(&gcpImageIDs, "image", nil, "image name or resource link (repeat to scan several; the default is every project image and every image an instance in this region uses)")
	scanWorkloadImageCmd.AddCommand(scanWorkloadImageAWSCmd, scanWorkloadImageAzureCmd, scanWorkloadImageGCPCmd)
	scanWorkloadCmd.AddCommand(scanWorkloadImageCmd)
}
