// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandleBlastRadiusRequiresIdentity(t *testing.T) {
	server := NewServer(nil, "")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/identity/blast-radius", nil)

	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "identity_id or name required" {
		t.Fatalf("error = %q", body["error"])
	}
}

func TestHandleBlastRadius(t *testing.T) {
	ctx := context.Background()
	store := openBlastRadiusStore(t)

	const (
		user = "identity:dev"
		role = "identity:admin"
		db   = "datastore:prod"
		net  = "network:public"
	)
	batch := graph.Batch{
		Nodes: []graph.Node{
			{ID: user, Type: graph.NodeIdentity, Name: "dev"},
			{ID: role, Type: graph.NodeIdentity, Name: "AdminRole"},
			{ID: db, Type: graph.NodeDatastore, Name: "prod-db"},
			{ID: net, Type: graph.NodeNetwork, Name: "public"},
		},
		Edges: []graph.Edge{
			{ID: user + "|" + role + "|" + graph.EdgeAssumes, SourceID: user, TargetID: role, Type: graph.EdgeAssumes},
			{ID: role + "|" + db + "|" + graph.EdgeCanAccess, SourceID: role, TargetID: db, Type: graph.EdgeCanAccess},
			{ID: user + "|" + net + "|" + graph.EdgeReachable, SourceID: user, TargetID: net, Type: graph.EdgeReachable},
		},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	handler := NewServer(store, "").Handler()
	wantIDs := db + "," + role

	t.Run("identity id", func(t *testing.T) {
		result := getBlastRadius(t, handler, "/v1/identity/blast-radius?identity_id="+url.QueryEscape(user))
		if result.Identity.Name != "dev" || result.MaxDepth != 6 {
			t.Fatalf("identity = %q depth %d", result.Identity.Name, result.MaxDepth)
		}
		if got := blastRadiusIDs(result); got != wantIDs {
			t.Fatalf("reachable = %s, want %s", got, wantIDs)
		}
	})

	t.Run("name", func(t *testing.T) {
		result := getBlastRadius(t, handler, "/v1/identity/blast-radius?name=dev")
		if result.Identity.ID != user {
			t.Fatalf("identity id = %s, want %s", result.Identity.ID, user)
		}
		if got := blastRadiusIDs(result); got != wantIDs {
			t.Fatalf("reachable = %s, want %s", got, wantIDs)
		}
	})

	t.Run("unknown name", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/identity/blast-radius?name=missing", nil)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
		}
	})
}

func getBlastRadius(t *testing.T, handler http.Handler, path string) graph.BlastRadiusResult {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var result graph.BlastRadiusResult
	if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return result
}

func blastRadiusIDs(result graph.BlastRadiusResult) string {
	ids := make([]string, len(result.Reachable))
	for i, node := range result.Reachable {
		ids[i] = node.ID
	}
	return strings.Join(ids, ",")
}

func openBlastRadiusStore(t *testing.T) *graph.Store {
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
	dbName := "ombr" + hex.EncodeToString(raw[:])
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

	if err := migrate.Run(ctx, databaseURL.String(), blastRadiusMigrationsDir(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store, err := graph.NewStore(ctx, databaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func blastRadiusMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
