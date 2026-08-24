// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/spf13/cobra"
)

var pathsCmd = &cobra.Command{
	Use:   "paths",
	Short: "Run named attack-path queries",
}

var pathsRunCmd = &cobra.Command{
	Use:   "run [query-name]",
	Short: "Execute a named path query",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		querier := graph.NewQuerier(store)
		result, err := querier.Run(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		fmt.Printf("Query: %s\n", result.Query)
		fmt.Printf("%s\n\n", result.Summary)
		if len(result.Paths) == 0 {
			fmt.Println("No paths found.")
			return nil
		}
		for i, path := range result.Paths {
			fmt.Printf("%d. %s\n", i+1, graph.FormatPath(path))
		}
		return nil
	},
}

var pathsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available path queries",
	Run: func(cmd *cobra.Command, args []string) {
		for name, desc := range graph.NamedQueries {
			fmt.Printf("  %s — %s\n", name, desc)
		}
	},
}

func init() {
	pathsCmd.AddCommand(pathsRunCmd)
	pathsCmd.AddCommand(pathsListCmd)
}
