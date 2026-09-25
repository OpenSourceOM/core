// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/collectors/azure"
	"github.com/OpenSourceOM/core/internal/collectors/demo"
	"github.com/OpenSourceOM/core/internal/collectors/gcp"
	"github.com/OpenSourceOM/core/internal/collectors/k8s"
	"github.com/OpenSourceOM/core/internal/config"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/plugins"
	"github.com/OpenSourceOM/core/internal/rules"
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

var pluginTimeout time.Duration

var scanPluginCmd = &cobra.Command{
	Use:   "plugin [--] <executable> [args...]",
	Short: "Run an external collector plugin and ingest its graph batch",
	Long: `Run a collector plugin and upsert the graph batch it writes to stdout.

The executable inherits om's environment. On success, stdout must be one JSON
object with "nodes" and "edges" (package sdk/collector). Diagnostics go to
stderr. Put plugin flags after -- so om does not parse them:

  om scan plugin --timeout 5m -- ./my-collector --region us-east-1`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		exe := args[0]
		pluginArgs := args[1:]
		label := fmt.Sprintf("plugin %s", filepath.Base(exe))
		return ingestScan(cmd.Context(), cfg, label, func(ctx context.Context) (graph.Batch, error) {
			runCtx, cancel := context.WithTimeout(ctx, pluginTimeout)
			defer cancel()
			return plugins.Run(runCtx, exe, pluginArgs)
		})
	},
}

var scanDemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Load a sample environment and print the attack path (no cloud credentials)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		ctx := cmd.Context()
		store, err := openGraphStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		if err := store.DeleteByAccount(ctx, demo.AccountIDs()); err != nil {
			return err
		}
		batch := demo.Collect()
		if err := store.UpsertBatch(ctx, batch); err != nil {
			return err
		}
		fmt.Printf("Ingested %d nodes and %d edges from demo sample environment.\n", len(batch.Nodes), len(batch.Edges))

		engine := rules.NewEngine(store)
		result, err := engine.RunAll(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Ran %d rules, created/updated %d findings.\n\n", len(rules.Catalog), result.FindingsCreated)

		hops, err := demo.AttackHops(batch)
		if err != nil {
			return err
		}
		fmt.Println("Attack path:")
		names := make([]string, 0, len(hops)+1)
		names = append(names, hops[0].SourceName)
		for _, hop := range hops {
			names = append(names, hop.TargetName)
		}
		fmt.Printf("  %s\n\n", strings.Join(names, " → "))
		for _, hop := range hops {
			fmt.Printf("  %s → %s (%s)\n    %s\n", hop.SourceName, hop.TargetName, hop.Type, hop.Reason)
		}

		findings, err := store.ListFindings(ctx, 200)
		if err != nil {
			return err
		}
		fmt.Println("\nHighest findings:")
		shown := 0
		demoAccounts := map[string]bool{demo.AccountID: true, demo.K8sAccountID: true}
		for _, view := range findings {
			if !demoAccounts[view.Finding.AccountID] {
				continue
			}
			if shown == 8 {
				break
			}
			shown++
			props := view.Finding.Properties
			fmt.Printf("  %s %v  %s  %s\n    %s\n",
				propString(props, "severity"),
				props["normalized_score"],
				view.Finding.Name,
				view.AffectedResourceName,
				propString(props, "description"),
			)
		}
		return nil
	},
}

func propString(props map[string]any, key string) string {
	value, ok := props[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
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
	scanPluginCmd.Flags().DurationVar(&pluginTimeout, "timeout", 10*time.Minute, "maximum time to wait for the plugin")
	scanCmd.AddCommand(scanDemoCmd)
	scanCmd.AddCommand(scanPluginCmd)
	scanCmd.AddCommand(scanAWSCmd)
	scanCmd.AddCommand(scanAzureCmd)
	scanCmd.AddCommand(scanGCPCmd)
	scanCmd.AddCommand(scanK8sCmd)
}
