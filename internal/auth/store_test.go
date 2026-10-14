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

	first, err := store.Bootstrap(ctx, Identity{
		Provider: ProviderGitHub,
		Subject:  "100",
		Login:    "ada",
		Name:     "Ada",
		Emails:   []string{"ada@example.com"},
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, err := store.Bootstrap(ctx, Identity{Provider: ProviderGitHub, Subject: "200", Login: "other", Emails: []string{"other@example.com"}}); err != ErrAdminsExist {
		t.Fatalf("second bootstrap = %v", err)
	}
	has, err := store.HasToken(ctx, first.ID)
	if err != nil || has {
		t.Fatalf("has token = %v err=%v", has, err)
	}
	if _, err := store.CreateToken(ctx, "not-a-uuid"); err != ErrNotFound {
		t.Fatalf("create missing = %v", err)
	}
	created, err := store.CreateToken(ctx, first.ID)
	if err != nil || created == "" {
		t.Fatalf("create token = %q err=%v", created, err)
	}
	if _, err := store.CreateToken(ctx, first.ID); err != ErrTokenExists {
		t.Fatalf("second create = %v", err)
	}
	loadedToken, err := store.AdminForToken(ctx, created)
	if err != nil || loadedToken.ID != first.ID {
		t.Fatalf("token admin = %+v err=%v", loadedToken, err)
	}
	rotated, err := store.RotateToken(ctx, first.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := store.AdminForToken(ctx, created); err != ErrNotFound {
		t.Fatalf("old token = %v", err)
	}
	if got, err := store.AdminForToken(ctx, rotated); err != nil || got.ID != first.ID {
		t.Fatalf("rotated token = %+v err=%v", got, err)
	}
	if err := store.Delete(ctx, first.ID); err != ErrLastAdmin {
		t.Fatalf("delete only admin = %v", err)
	}

	again, found, err := store.Find(ctx, ProviderGitHub, "100")
	if err != nil || !found || again.ID != first.ID {
		t.Fatalf("find = %+v found=%v err=%v", again, found, err)
	}

	invite, _, err := store.CreateInvite(ctx, first.ID, "Ada@Example.com")
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := store.AcceptInvite(ctx, invite, Identity{Provider: ProviderGoogle, Subject: "nope", Login: "nope", Emails: []string{"other@example.com"}}); err != ErrEmailMismatch {
		t.Fatalf("mismatch = %v", err)
	}
	same, err := store.AcceptInvite(ctx, invite, Identity{Provider: ProviderGitHub, Subject: "100", Login: "ada", Emails: []string{"ada@example.com"}})
	if err != nil {
		t.Fatalf("existing admin accept: %v", err)
	}
	if same.ID != first.ID {
		t.Fatalf("existing admin id = %s", same.ID)
	}
	if err := store.PeekInvite(ctx, invite); err != nil {
		t.Fatalf("unused invite after existing login: %v", err)
	}

	second, err := store.AcceptInvite(ctx, invite, Identity{Provider: ProviderGoogle, Subject: "gsub", Login: "ada", Name: "Ada Lovelace", Emails: []string{"ada@example.com"}})
	if err != nil {
		t.Fatalf("accept second: %v", err)
	}
	if second.Email != "ada@example.com" {
		t.Fatalf("email = %s", second.Email)
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
	if err != nil || loaded.ID != second.ID || loaded.Login != "ada" || loaded.Email != "ada@example.com" {
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

func TestPasswordResetReplacesThePasswordAndSessions(t *testing.T) {
	store := openAuthStore(t)
	ctx := context.Background()
	admin, err := store.SetupAdmin(ctx, "ada@example.com", "correct-horse-battery", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWithPassword(ctx, "temp@example.com", "temporary-password", true); err != nil {
		t.Fatal(err)
	}
	if token, err := store.RequestPasswordReset(ctx, "nobody@example.com"); err != nil || token != "" {
		t.Fatalf("unknown = %q err=%v", token, err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO admins (provider, subject, login, email)
		VALUES ('github', '9', 'octo', 'octo@example.com')
	`); err != nil {
		t.Fatal(err)
	}
	if token, err := store.RequestPasswordReset(ctx, "octo@example.com"); err != nil || token != "" {
		t.Fatalf("oauth = %q err=%v", token, err)
	}

	first, err := store.RequestPasswordReset(ctx, "Ada@Example.com")
	if err != nil || first == "" {
		t.Fatalf("first token = %q err=%v", first, err)
	}
	second, err := store.RequestPasswordReset(ctx, "ada@example.com")
	if err != nil || second == "" || second == first {
		t.Fatalf("second token = %q err=%v", second, err)
	}
	if err := store.CompletePasswordReset(ctx, first, "another-password-ok"); err != ErrResetInvalid {
		t.Fatalf("replaced token = %v", err)
	}
	if err := store.CompletePasswordReset(ctx, second, "short"); err != ErrPasswordShort {
		t.Fatalf("short = %v", err)
	}
	session, _, err := store.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePasswordReset(ctx, second, "a-new-password-ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdminForSession(ctx, session); err != ErrNotFound {
		t.Fatalf("session after reset = %v", err)
	}
	if _, err := store.CheckPassword(ctx, "ada@example.com", "correct-horse-battery"); err != ErrBadCredentials {
		t.Fatalf("old password = %v", err)
	}
	if _, err := store.CheckPassword(ctx, "ada@example.com", "a-new-password-ok"); err != nil {
		t.Fatalf("new password = %v", err)
	}
	if err := store.CompletePasswordReset(ctx, second, "another-password-ok"); err != ErrResetInvalid {
		t.Fatalf("reuse = %v", err)
	}

	tempToken, err := store.RequestPasswordReset(ctx, "temp@example.com")
	if err != nil || tempToken == "" {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE admin_password_resets SET expires_at = now() - interval '1 minute' WHERE id = $1`, HashToken(tempToken)); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePasswordReset(ctx, tempToken, "another-password-ok"); err != ErrResetInvalid {
		t.Fatalf("expired = %v", err)
	}
	loaded, found, err := store.FindByEmail(ctx, "temp@example.com")
	if err != nil || !found || !loaded.MustChangePassword {
		t.Fatalf("temp admin = %+v found=%v err=%v", loaded, found, err)
	}
}

func TestStoreExpiredInvite(t *testing.T) {
	store := openAuthStore(t)
	ctx := context.Background()
	first, err := store.Bootstrap(ctx, Identity{Provider: ProviderGitHub, Subject: "1", Login: "ada", Emails: []string{"ada@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateInvite(ctx, first.ID, "next@example.com")
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
