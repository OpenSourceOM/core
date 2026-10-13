// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

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
		logBootstrap(cmd.Context(), admins, providers, cfg.PublicURL)

		server := api.NewServer(store, cfg.APISecret).WithConsoleAuth(api.ConsoleAuth{
			Directory: admins,
			PublicURL: cfg.PublicURL,
			Providers: providers,
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

func logBootstrap(ctx context.Context, admins *auth.Store, providers map[string]auth.Provider, publicURL string) {
	count, err := admins.Count(ctx)
	if err != nil {
		log.Printf("console admins: %v", err)
		return
	}
	if count > 0 {
		return
	}
	if len(providers) == 0 {
		log.Printf("no console admin yet; set OM_GOOGLE_CLIENT_ID and OM_GOOGLE_CLIENT_SECRET, or OM_GITHUB_CLIENT_ID and OM_GITHUB_CLIENT_SECRET, then restart the API")
		return
	}
	token, expires, err := admins.RotateBootstrapInvite(ctx)
	if errors.Is(err, auth.ErrAdminsExist) {
		return
	}
	if err != nil {
		log.Printf("console setup link: %v", err)
		return
	}
	base := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	log.Printf("OpenSourceOM setup link (expires %s): %s/setup/%s", expires.UTC().Format(time.RFC3339), base, token)
}
