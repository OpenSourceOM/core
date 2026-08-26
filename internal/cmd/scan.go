// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	"github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/collectors/azure"
	"github.com/OpenSourceOM/core/internal/collectors/demo"
	"github.com/OpenSourceOM/core/internal/collectors/gcp"
	"github.com/OpenSourceOM/core/internal/collectors/k8s"
	"github.com/OpenSourceOM/core/internal/config"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run cloud collectors and ingest into the graph",
}

var scanAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Scan the current AWS account (EC2, IAM, S3, security groups)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		collector, err := aws.NewCollector(cmd.Context(), cfg.AWSRegion)
		if err != nil {
			return err
		}
		return ingestScan(cmd.Context(), cfg, fmt.Sprintf("AWS account %s (%s)", collector.AccountID, cfg.AWSRegion), func(ctx context.Context) (graph.Batch, error) {
			return collector.Collect(ctx)
		})
	},
}

var scanAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Scan the current Azure subscription (VMs, storage, RBAC)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		collector := azure.NewCollector(cfg.AzureSubscriptionID, cfg.AzureLocation)
		return ingestScan(cmd.Context(), cfg, fmt.Sprintf("Azure subscription %s", cfg.AzureSubscriptionID), collector.Collect)
	},
}

var scanGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Scan the current GCP project (GCE, IAM, GCS)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		collector := gcp.NewCollector(cfg.GCPProjectID, cfg.GCPRegion)
		return ingestScan(cmd.Context(), cfg, fmt.Sprintf("GCP project %s", cfg.GCPProjectID), collector.Collect)
	},
}

var scanK8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Scan a Kubernetes cluster (pods, services, service accounts)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		collector := k8s.NewCollector(cfg.K8sCluster, cfg.K8sNamespace)
		label := fmt.Sprintf("Kubernetes cluster %s", cfg.K8sCluster)
		if cfg.K8sNamespace != "" {
			label += " namespace " + cfg.K8sNamespace
		}
		return ingestScan(cmd.Context(), cfg, label, collector.Collect)
	},
}

var scanDemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Load a sample environment (no cloud credentials)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		return ingestScan(cmd.Context(), cfg, "demo sample environment", func(ctx context.Context) (graph.Batch, error) {
			return demo.Collect(), nil
		})
	},
}

func ingestScan(ctx context.Context, cfg config.Config, label string, collect func(context.Context) (graph.Batch, error)) error {
	store, err := openGraphStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	batch, err := collect(ctx)
	if err != nil {
		return err
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		return err
	}

	fmt.Printf("Ingested %d nodes and %d edges from %s.\n", len(batch.Nodes), len(batch.Edges), label)
	return nil
}

func init() {
	scanCmd.AddCommand(scanDemoCmd)
	scanCmd.AddCommand(scanAWSCmd)
	scanCmd.AddCommand(scanAzureCmd)
	scanCmd.AddCommand(scanGCPCmd)
	scanCmd.AddCommand(scanK8sCmd)
}
