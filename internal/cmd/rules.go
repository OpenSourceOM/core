// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/OpenSourceOM/core/internal/rules"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Run CSPM rules against the graph",
}

var rulesRunCmd = &cobra.Command{
	Use:   "run [rule-id]",
	Short: "Evaluate CSPM rules and write graph-context findings",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		engine := rules.NewEngine(store)
		if len(args) == 0 {
			result, err := engine.RunAll(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("Ran %d rules, created/updated %d findings.\n", len(rules.Catalog), result.FindingsCreated)
			return nil
		}

		result, err := engine.Run(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		fmt.Printf("Rule %s matched %d resources (%d findings written).\n", args[0], len(result.Matches), result.FindingsCreated)
		return nil
	},
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available CSPM rules",
	Run: func(cmd *cobra.Command, args []string) {
		for _, rule := range rules.Catalog {
			fmt.Printf("  %s — %s\n", rule.ID, rule.Description)
		}
	},
}

func init() {
	rulesCmd.AddCommand(rulesRunCmd)
	rulesCmd.AddCommand(rulesListCmd)
}
