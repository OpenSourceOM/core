// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Inspect the security graph",
}

var graphStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show node and edge counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		stats, err := store.Stats(cmd.Context())
		if err != nil {
			return err
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(stats)
	},
}

func init() {
	graphCmd.AddCommand(graphStatsCmd)
}
