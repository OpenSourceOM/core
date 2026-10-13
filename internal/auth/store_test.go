// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreInviteSessionAndLastAdmin(t *testing.T) {
	store := openAuthStore(t)
	ctx := context.Background()

	token, _, err := store.RotateBootstrapInvite(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := store.PeekInvite(ctx, token); err != nil {
		t.Fatalf("peek bootstrap: %v", err)
	}

	first, err := store.AcceptInvite(ctx, token, Identity{
		Provider: ProviderGitHub,
		Subject:  "100",
		Login:    "ada",
		Name:     "Ada",
	})
	if err != nil {
		t.Fatalf("accept bootstrap: %v", err)
	}
	if err := store.PeekInvite(ctx, token); err != ErrInviteUsed {
		t.Fatalf("consumed invite peek = %v", err)
	}
	if _, err := store.AcceptInvite(ctx, token, Identity{Provider: ProviderGitHub, Subject: "200", Login: "other"}); err != ErrInviteUsed {
		t.Fatalf("second accept = %v", err)
	}
	if _, _, err := store.RotateBootstrapInvite(ctx); err != ErrAdminsExist {
		t.Fatalf("rotate after admin = %v", err)
	}
	if err := store.Delete(ctx, first.ID); err != ErrLastAdmin {
		t.Fatalf("delete only admin = %v", err)
	}

	again, found, err := store.Find(ctx, ProviderGitHub, "100")
	if err != nil || !found || again.ID != first.ID {
		t.Fatalf("find = %+v found=%v err=%v", again, found, err)
	}

	invite, _, err := store.CreateInvite(ctx, first.ID)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	same, err := store.AcceptInvite(ctx, invite, Identity{Provider: ProviderGitHub, Subject: "100", Login: "ada"})
	if err != nil {
		t.Fatalf("existing admin accept: %v", err)
	}
	if same.ID != first.ID {
		t.Fatalf("existing admin id = %s", same.ID)
	}
	if err := store.PeekInvite(ctx, invite); err != nil {
		t.Fatalf("unused invite after existing login: %v", err)
	}

	second, err := store.AcceptInvite(ctx, invite, Identity{Provider: ProviderGoogle, Subject: "gsub", Login: "ada@example.com", Name: "Ada Lovelace"})
	if err != nil {
		t.Fatalf("accept second: %v", err)
	}
	admins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(admins) != 2 {
		t.Fatalf("admins = %d", len(admins))
	}

	session, expires, err := store.CreateSession(ctx, second.ID)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if !expires.After(time.Now().Add(6 * 24 * time.Hour)) {
		t.Fatalf("session expires too soon: %s", expires)
	}
	loaded, err := store.AdminForSession(ctx, session)
	if err != nil || loaded.ID != second.ID || loaded.Login != "ada@example.com" {
		t.Fatalf("session admin = %+v err=%v", loaded, err)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE admin_sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`, HashToken(session)); err != nil {
		t.Fatalf("expire session: %v", err)
	}
	if _, err := store.AdminForSession(ctx, session); err != ErrNotFound {
		t.Fatalf("expired session = %v", err)
	}

	if err := store.Delete(ctx, first.ID); err != nil {
		t.Fatalf("delete first: %v", err)
	}
	if err := store.Delete(ctx, second.ID); err != ErrLastAdmin {
		t.Fatalf("delete remaining = %v", err)
	}
	if err := store.Delete(ctx, "not-a-uuid"); err != ErrNotFound {
		t.Fatalf("bad id = %v", err)
	}
}

func TestStoreExpiredInvite(t *testing.T) {
	store := openAuthStore(t)
	ctx := context.Background()
	token, _, err := store.RotateBootstrapInvite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE admin_invites SET expires_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if err := store.PeekInvite(ctx, token); err != ErrInviteExpired {
		t.Fatalf("peek = %v", err)
	}
}

func openAuthStore(t *testing.T) *Store {
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
	dbName := "omauth" + hex.EncodeToString(raw[:])
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
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	migrations := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	if err := migrate.Run(ctx, databaseURL.String(), migrations); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store, err := NewStore(ctx, databaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}
