// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/connect"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Show how to grant a cloud account for scanning",
	Long: `Print the same steps as Settings → Connect a cloud.

The console generates an external id, opens the grant, and can run the inventory scan. This command prints the steps and can verify credentials already on this machine. It does not ask for an access key.`,
}

var connectAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Show how to connect an AWS account",
	RunE: func(cmd *cobra.Command, args []string) error {
		return printConnect(cmd, "aws")
	},
}

var connectAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Show how to connect an Azure subscription",
	RunE: func(cmd *cobra.Command, args []string) error {
		return printConnect(cmd, "azure")
	},
}

var connectGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Show how to connect a GCP project",
	RunE: func(cmd *cobra.Command, args []string) error {
		return printConnect(cmd, "gcp")
	},
}

var (
	connectVerifyRole       string
	connectVerifyExternalID string
	connectVerifyRegion     string
	connectVerifyAccount    string
	connectVerifyLocation   string
)

var connectVerifyCmd = &cobra.Command{
	Use:   "verify [aws|azure|gcp]",
	Short: "Check that this machine can read a cloud account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, err := connect.New(args[0], connectVerifyRegion)
		if err != nil {
			return err
		}
		conn.AccountID = connectVerifyAccount
		conn.InventoryRoleARN = connectVerifyRole
		conn.Location = connectVerifyLocation
		if connectVerifyExternalID != "" {
			conn.ExternalID = connectVerifyExternalID
		}
		if err := connect.Validate(conn); err != nil {
			return err
		}
		identity, err := connect.Verify(cmd.Context(), conn, "inventory")
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n%s\n", identity.Provider, identity.AccountID, identity.Principal)
		return nil
	},
}

func printConnect(cmd *cobra.Command, provider string) error {
	conn, err := connect.New(provider, "")
	if err != nil {
		return err
	}
	setup, err := connect.Present(conn)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Settings → Connect a cloud saves an external id and opens these grants.")
	fmt.Fprintf(out, "This command's external id is %s. It is not saved. Use it only if you open the links below now.\n", conn.ExternalID)
	fmt.Fprintln(out, "Do not paste an access key or a client secret.")
	for i, step := range setup.Steps {
		fmt.Fprintf(out, "%d. %s\n", i+1, step)
	}
	fmt.Fprintln(out)
	for _, link := range setup.Links {
		fmt.Fprintf(out, "%s\n", link.Label)
		if link.URL != "" {
			fmt.Fprintf(out, "  %s\n", link.URL)
		}
		if link.Template != "" {
			fmt.Fprintf(out, "  download: GET /v1/connect/templates/%s\n", link.Template)
		}
		if link.Note != "" {
			fmt.Fprintf(out, "  %s\n", link.Note)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Inventory scan, on this machine:")
	switch provider {
	case "aws":
		fmt.Fprintln(out, "  om scan aws --role-arn \"$ROLE_ARN\" --external-id \"$EXTERNAL_ID\"")
	case "azure":
		fmt.Fprintln(out, "  AZURE_SUBSCRIPTION_ID=... om scan azure")
	case "gcp":
		fmt.Fprintln(out, "  GCP_PROJECT_ID=... om scan gcp")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Package scan, as root on the worker:")
	command := strings.ReplaceAll(setup.WorkloadCommand, conn.ExternalID, "$EXTERNAL_ID")
	fmt.Fprintf(out, "  %s\n", command)
	return nil
}

func init() {
	connectVerifyCmd.Flags().StringVar(&connectVerifyRole, "role-arn", "", "AWS inventory role to assume")
	connectVerifyCmd.Flags().StringVar(&connectVerifyExternalID, "external-id", "", "external id for that role")
	connectVerifyCmd.Flags().StringVar(&connectVerifyRegion, "region", "", "AWS or GCP region")
	connectVerifyCmd.Flags().StringVar(&connectVerifyAccount, "account", "", "subscription id or project id")
	connectVerifyCmd.Flags().StringVar(&connectVerifyLocation, "location", "", "Azure location")
	connectCmd.AddCommand(connectAWSCmd, connectAzureCmd, connectGCPCmd, connectVerifyCmd)
}
