// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Identity analysis commands",
}

var (
	identityID   string
	identityName string
)

var identityBlastRadiusCmd = &cobra.Command{
	Use:   "blast-radius",
	Short: "Show resources reachable from an identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		targetID := identityID
		if targetID == "" && identityName != "" {
			node, err := store.FindIdentityByName(cmd.Context(), identityName)
			if err != nil {
				return fmt.Errorf("find identity %q: %w", identityName, err)
			}
			targetID = node.ID
		}
		if targetID == "" {
			return fmt.Errorf("provide --id or --name")
		}

		result, err := store.BlastRadius(cmd.Context(), targetID, 6)
		if err != nil {
			return err
		}

		if blastRadiusJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}

		fmt.Println(result.Summary)
		for _, node := range result.Reachable {
			fmt.Printf("  - %s (%s)\n", node.Name, node.Type)
		}

		return nil
	},
}

var blastRadiusJSON bool

func init() {
	identityBlastRadiusCmd.Flags().StringVar(&identityID, "id", "", "Identity node ID")
	identityBlastRadiusCmd.Flags().StringVar(&identityName, "name", "", "Identity name")
	identityBlastRadiusCmd.Flags().BoolVar(&blastRadiusJSON, "json", false, "Output JSON")
	identityCmd.AddCommand(identityBlastRadiusCmd)
}
