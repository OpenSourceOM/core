// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		applied, err := runMigrations(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			fmt.Println("Database schema is current.")
			return nil
		}
		for _, version := range applied {
			fmt.Printf("applied %s\n", version)
		}
		fmt.Println("Migrations applied.")
		return nil
	},
}
