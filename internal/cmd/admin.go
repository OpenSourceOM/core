// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OpenSourceOM/core/internal/auth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var adminEmail string

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Create and reset console admin passwords",
}

var adminCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a console admin",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		email, err := auth.NormalizeEmail(adminEmail)
		if err != nil {
			return fmt.Errorf("pass --email")
		}
		admins, err := auth.NewStore(cmd.Context(), cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer admins.Close()
		count, err := admins.Count(cmd.Context())
		if err != nil {
			return err
		}
		if count == 0 && cfg.AdminEmail != "" {
			pinned, err := auth.NormalizeEmail(cfg.AdminEmail)
			if err != nil {
				return fmt.Errorf("OM_ADMIN_EMAIL is not a valid email")
			}
			if email != pinned {
				return fmt.Errorf("the first admin must be %s", pinned)
			}
		}
		password, err := promptPassword("Password: ")
		if err != nil {
			return err
		}
		again, err := promptPassword("Confirm password: ")
		if err != nil {
			return err
		}
		if password != again {
			return fmt.Errorf("passwords do not match")
		}
		if _, err := admins.CreateWithPassword(cmd.Context(), email, password, false); err != nil {
			if errors.Is(err, auth.ErrPasswordShort) {
				return fmt.Errorf("use at least 12 characters")
			}
			if errors.Is(err, auth.ErrEmailTaken) {
				return fmt.Errorf("an admin with that email already exists")
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "created admin %s\n", email)
		return nil
	},
}

var adminResetCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "Set a new password for an existing admin",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		email, err := auth.NormalizeEmail(adminEmail)
		if err != nil {
			return fmt.Errorf("pass --email")
		}
		admins, err := auth.NewStore(cmd.Context(), cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer admins.Close()
		password, err := promptPassword("New password: ")
		if err != nil {
			return err
		}
		again, err := promptPassword("Confirm password: ")
		if err != nil {
			return err
		}
		if password != again {
			return fmt.Errorf("passwords do not match")
		}
		if err := admins.SetPassword(cmd.Context(), email, password); err != nil {
			if errors.Is(err, auth.ErrNotFound) {
				return fmt.Errorf("no password admin with that email")
			}
			if errors.Is(err, auth.ErrPasswordShort) {
				return fmt.Errorf("use at least 12 characters")
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "updated password for %s\n", email)
		return nil
	},
}

func init() {
	adminCmd.AddCommand(adminCreateCmd)
	adminCmd.AddCommand(adminResetCmd)
	adminCmd.PersistentFlags().StringVar(&adminEmail, "email", "", "Admin email address")
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
