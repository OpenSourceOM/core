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
		if err := runMigrations(cmd.Context(), cfg); err != nil {
			return err
		}
		fmt.Println("Migrations applied.")
		return nil
	},
}
