// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/OpenSourceOM/core/internal/auth"
	"github.com/spf13/cobra"
)

var tokenEmail string

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Create or rotate a personal API token",
}

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an API token for an admin and print it once",
	RunE: func(cmd *cobra.Command, args []string) error {
		admins, email, err := openTokenStore(cmd)
		if err != nil {
			return err
		}
		defer admins.Close()
		admin, found, err := admins.FindByEmail(cmd.Context(), email)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("no admin with that email")
		}
		token, err := admins.CreateToken(cmd.Context(), admin.ID)
		if errors.Is(err, auth.ErrTokenExists) {
			return fmt.Errorf("an API token already exists for %s. Run `om token rotate --email %s` to replace it", email, email)
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, token)
		fmt.Fprintf(os.Stderr, "API token for %s. It will not be shown again.\n", email)
		warnIfPasswordChangePending(admin)
		return nil
	},
}

var tokenRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace an admin's API token and print the new one once",
	RunE: func(cmd *cobra.Command, args []string) error {
		admins, email, err := openTokenStore(cmd)
		if err != nil {
			return err
		}
		defer admins.Close()
		admin, found, err := admins.FindByEmail(cmd.Context(), email)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("no admin with that email")
		}
		has, err := admins.HasToken(cmd.Context(), admin.ID)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("no API token for %s. Run `om token create --email %s`", email, email)
		}
		token, err := admins.RotateToken(cmd.Context(), admin.ID)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, token)
		fmt.Fprintf(os.Stderr, "Replaced the API token for %s. The previous token no longer works. This value will not be shown again.\n", email)
		warnIfPasswordChangePending(admin)
		return nil
	},
}

func init() {
	tokenCmd.AddCommand(tokenCreateCmd)
	tokenCmd.AddCommand(tokenRotateCmd)
	tokenCmd.PersistentFlags().StringVar(&tokenEmail, "email", "", "Admin email address")
}

func warnIfPasswordChangePending(admin auth.Admin) {
	if admin.MustChangePassword {
		fmt.Fprintf(os.Stderr, "The API will reject this token until %s chooses a password.\n", admin.Email)
	}
}

func openTokenStore(cmd *cobra.Command) (*auth.Store, string, error) {
	email, err := auth.NormalizeEmail(tokenEmail)
	if err != nil {
		return nil, "", fmt.Errorf("pass --email")
	}
	cfg := loadConfig()
	admins, err := auth.NewStore(cmd.Context(), cfg.DatabaseURL)
	if err != nil {
		return nil, "", err
	}
	return admins, email, nil
}
