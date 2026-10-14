// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// lockSQL is a session advisory lock so two processes cannot apply the same file.
// The Helm init container and om serve can both call Run against one database.
const (
	lockSQL   = `SELECT pg_advisory_lock(hashtext('opensourceom.migrate'))`
	unlockSQL = `SELECT pg_advisory_unlock(hashtext('opensourceom.migrate'))`
)

// Run applies pending SQL migrations. Applied versions are skipped.
// Each file and its schema_migrations row commit together.
// The returned names are the versions applied by this call.
func Run(ctx context.Context, databaseURL, migrationsDir string) ([]string, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	defer conn.Close(context.Background())

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if _, err := conn.Exec(ctx, lockSQL); err != nil {
		return nil, fmt.Errorf("lock migrations: %w", err)
	}
	defer conn.Exec(context.Background(), unlockSQL)

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	var applied []string
	for _, file := range files {
		version := strings.TrimSuffix(file, ".sql")
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			continue
		}

		sqlBytes, err := os.ReadFile(filepath.Join(migrationsDir, file))
		if err != nil {
			return nil, err
		}
		if err := applyFile(ctx, conn, version, string(sqlBytes)); err != nil {
			return nil, err
		}
		applied = append(applied, version)
	}

	return applied, nil
}

// applyFile runs the file and records its version as one simple-protocol batch.
// Postgres treats that batch as a single transaction, so a failed statement
// leaves neither the schema change nor the version row.
func applyFile(ctx context.Context, conn *pgx.Conn, version, sqlText string) error {
	statement := strings.TrimSpace(sqlText)
	if statement != "" && !strings.HasSuffix(statement, ";") {
		statement += ";"
	}
	statement += "\nINSERT INTO schema_migrations (version) VALUES (" + quoteLiteral(version) + ") ON CONFLICT DO NOTHING;"

	if _, err := conn.Exec(ctx, statement); err != nil {
		return fmt.Errorf("apply migration %s: %w", version, err)
	}
	return nil
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
