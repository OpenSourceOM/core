// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunAppliesRepoMigrationsOnce(t *testing.T) {
	ctx := context.Background()
	databaseURL := newDatabase(t)

	applied, err := Run(ctx, databaseURL, repoMigrations(t))
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("first run applied nothing")
	}

	again, err := Run(ctx, databaseURL, repoMigrations(t))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second run applied %v", again)
	}
}

func TestRunAppliesOnlyPendingFiles(t *testing.T) {
	ctx := context.Background()
	databaseURL := newDatabase(t)
	dir := t.TempDir()
	writeMigration(t, dir, "001_first.sql", "CREATE TABLE first_only (id int);")

	applied, err := Run(ctx, databaseURL, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "001_first" {
		t.Fatalf("first apply = %v", applied)
	}

	writeMigration(t, dir, "002_second.sql", "CREATE TABLE second_only (id int);")
	applied, err = Run(ctx, databaseURL, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "002_second" {
		t.Fatalf("pending apply = %v", applied)
	}
}

func TestRunRollsBackFailedFile(t *testing.T) {
	ctx := context.Background()
	databaseURL := newDatabase(t)
	dir := t.TempDir()
	writeMigration(t, dir, "001_bad.sql", "CREATE TABLE should_rollback (id int);\nSELECT 1/0;")

	if _, err := Run(ctx, databaseURL, dir); err == nil {
		t.Fatal("expected migration error")
	}

	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })

	var tableExists, versionExists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'should_rollback')`).Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '001_bad')`).Scan(&versionExists); err != nil {
		t.Fatal(err)
	}
	if tableExists || versionExists {
		t.Fatalf("table=%v version=%v, want both absent", tableExists, versionExists)
	}
}

func TestRunSerializesConcurrentApplicators(t *testing.T) {
	ctx := context.Background()
	databaseURL := newDatabase(t)
	dir := t.TempDir()
	writeMigration(t, dir, "001_once.sql", "CREATE TABLE once_only (id int PRIMARY KEY);")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	applied := make(chan []string, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			versions, err := Run(ctx, databaseURL, dir)
			errs <- err
			applied <- versions
		}()
	}
	wg.Wait()
	close(errs)
	close(applied)

	var got []string
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for versions := range applied {
		got = append(got, versions...)
	}
	if len(got) != 1 || got[0] != "001_once" {
		t.Fatalf("applied = %v, want [001_once]", got)
	}
}

func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func repoMigrations(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func newDatabase(t *testing.T) string {
	t.Helper()
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(admin.Close)

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	dbName := "omm" + hex.EncodeToString(raw[:])
	ident := pgx.Identifier{dbName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+ident+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database %s: %v", dbName, err)
		}
	})

	databaseURL, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	databaseURL.Path = "/" + dbName
	return databaseURL.String()
}
