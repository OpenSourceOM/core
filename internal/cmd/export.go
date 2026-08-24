// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/OpenSourceOM/core/internal/export"
	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings to external systems",
}

var exportFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Export prioritized findings",
}

var (
	exportFormat string
	exportOut    string
)

var exportFindingsRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Export findings using the selected format",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		records, err := export.LoadFindingRecords(cmd.Context(), store)
		if err != nil {
			return err
		}

		switch exportFormat {
		case "siem":
			out := os.Stdout
			if exportOut != "" {
				out, err = os.Create(exportOut)
				if err != nil {
					return err
				}
				defer out.Close()
			}
			if err := export.WriteSIEM(out, records); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Exported %d findings to SIEM JSONL.\n", len(records))
		case "slack":
			if err := export.PostSlack(cmd.Context(), cfg.SlackWebhookURL, records); err != nil {
				return err
			}
			fmt.Printf("Posted %d findings to Slack.\n", len(records))
		case "jira":
			count, err := export.CreateJiraIssues(cmd.Context(), export.JiraConfig{
				BaseURL:  cfg.JiraURL,
				Email:    cfg.JiraEmail,
				APIToken: cfg.JiraAPIToken,
				Project:  cfg.JiraProject,
			}, records)
			if err != nil {
				return err
			}
			fmt.Printf("Created %d Jira issues.\n", count)
		default:
			return fmt.Errorf("unsupported format %q (use siem, slack, or jira)", exportFormat)
		}
		return nil
	},
}

func init() {
	exportFindingsCmd.PersistentFlags().StringVar(&exportFormat, "format", "siem", "Export format: siem, slack, jira")
	exportFindingsCmd.PersistentFlags().StringVar(&exportOut, "out", "", "Output file for SIEM export")
	exportFindingsCmd.AddCommand(exportFindingsRunCmd)
	exportCmd.AddCommand(exportFindingsCmd)
}
