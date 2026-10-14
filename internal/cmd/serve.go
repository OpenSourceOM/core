// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/OpenSourceOM/core/internal/api"
	"github.com/OpenSourceOM/core/internal/auth"
	"github.com/OpenSourceOM/core/internal/config"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadConfig()
		store, err := openGraphStore(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()

		admins, err := auth.NewStore(cmd.Context(), cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer admins.Close()

		warnOAuthConfig(cfg)
		providers := auth.ProvidersFromConfig(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GitHubClientID, cfg.GitHubClientSecret)

		sendPassword, sendReset := consoleMail(cfg)
		server := api.NewServer(store).WithConsoleAuth(api.ConsoleAuth{
			Directory:    admins,
			PublicURL:    cfg.PublicURL,
			Providers:    providers,
			SetupEmail:   cfg.AdminEmail,
			SendPassword: sendPassword,
			SendReset:    sendReset,
		})
		addr := fmt.Sprintf(":%d", cfg.APIPort)
		return server.ListenAndServe(addr)
	},
}

func warnOAuthConfig(cfg config.Config) {
	if (cfg.GoogleClientID == "") != (cfg.GoogleClientSecret == "") {
		log.Printf("Google console login needs both OM_GOOGLE_CLIENT_ID and OM_GOOGLE_CLIENT_SECRET")
	}
	if (cfg.GitHubClientID == "") != (cfg.GitHubClientSecret == "") {
		log.Printf("GitHub console login needs both OM_GITHUB_CLIENT_ID and OM_GITHUB_CLIENT_SECRET")
	}
}

func consoleMail(cfg config.Config) (func(context.Context, string, string) error, func(context.Context, string, string) error) {
	mailer := auth.InviteMailer{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	}
	if !mailer.Enabled() {
		return nil, nil
	}
	loginURL := strings.TrimRight(cfg.PublicURL, "/")
	if loginURL == "" {
		loginURL = "/"
	}
	sendPassword := func(ctx context.Context, to, password string) error {
		return mailer.SendTemporaryPassword(ctx, to, password, loginURL)
	}
	sendReset := func(ctx context.Context, to, resetURL string) error {
		return mailer.SendPasswordReset(ctx, to, resetURL)
	}
	return sendPassword, sendReset
}
