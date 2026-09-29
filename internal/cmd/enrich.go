// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/OpenSourceOM/core/internal/enrichment"
	"github.com/spf13/cobra"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich the graph with external security intelligence",
}

var (
	enrichCVEIDs       []string
	enrichInternetOnly bool
	enrichCatalog      string
)

var enrichCVECmd = &cobra.Command{
	Use:   "cve",
	Short: "Create CVE findings for workload packages and images",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		catalogPath := enrichCatalog
		if catalogPath == "" {
			catalogPath = cfg.CVECatalog
		}
		source, err := enrichment.OpenSource(cfg.NVDAPIKey, catalogPath)
		if err != nil {
			return err
		}
		enricher := enrichment.New(store, source)
		result, err := enricher.EnrichCVE(cmd.Context(), enrichment.Options{
			CVEIDs:       enrichCVEIDs,
			InternetOnly: enrichInternetOnly,
		})
		if err != nil {
			return err
		}

		fmt.Printf(
			"Enrichment complete: %d findings created, %d updated.\n",
			result.FindingsCreated, result.FindingsUpdated,
		)
		return nil
	},
}

func init() {
	enrichCVECmd.Flags().StringSliceVar(&enrichCVEIDs, "cve", nil, "CVE IDs to consider (repeatable). Each id still has to match inventory")
	enrichCVECmd.Flags().BoolVar(&enrichInternetOnly, "internet-only", true, "Only enrich internet-reachable workloads")
	enrichCVECmd.Flags().StringVar(&enrichCatalog, "catalog", "", "JSON CVE catalog to use instead of NVD")
	enrichCmd.AddCommand(enrichCVECmd)
}
