// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/OpenSourceOM/core/internal/config"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/migrate"
)

func repoPath(parts ...string) (string, error) {
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...), nil
}

func findRepoRoot() (string, error) {
	if root := os.Getenv("OM_REPO_ROOT"); root != "" {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root, nil
		}
	}

	dir, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

func loadConfig() config.Config {
	return config.Load()
}

func runMigrations(ctx context.Context, cfg config.Config) error {
	migrationsDir, err := repoPath("migrations")
	if err != nil {
		return err
	}
	return migrate.Run(ctx, cfg.DatabaseURL, migrationsDir)
}

func openGraphStore(ctx context.Context, cfg config.Config) (*graph.Store, error) {
	return graph.NewStore(ctx, cfg.DatabaseURL)
}
