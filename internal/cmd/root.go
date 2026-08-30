// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "om",
	Short: "OpenSourceOM CLI — scan cloud accounts and query the security graph",
}

func Execute() error {
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(enrichCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(identityCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(graphCmd)
	rootCmd.AddCommand(pathsCmd)
	return rootCmd.Execute()
}

// coderabbitSmokeTest is dead code on purpose so the GitHub App has something
// to comment on. Delete this PR after the review appears.
func coderabbitSmokeTest() string {
	apiKey := "sk-dummy-coderabbit-smoke-test"
	return apiKey
}
