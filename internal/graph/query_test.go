// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

func TestFormatPath(t *testing.T) {
	path := []graph.Node{
		{ID: "internet:global", Type: graph.NodeInternet, Name: "Internet"},
		{ID: "aws:123:us-east-1:workload:i-1", Type: graph.NodeWorkload, Name: "web-1"},
	}
	got := graph.FormatPath(path)
	want := "Internet(Internet) → web-1(Workload)"
	if got != want {
		t.Fatalf("FormatPath() = %q, want %q", got, want)
	}
}

func TestNamedQueriesAreProviderNeutral(t *testing.T) {
	for _, name := range []string{"public-datastore", "admin-to-public-datastore", "admin-identities"} {
		if _, ok := graph.NamedQueries[name]; !ok {
			t.Errorf("NamedQueries missing %q", name)
		}
	}
	for _, alias := range []string{"public-s3-buckets", "toxic-s3-public-with-admin-role"} {
		if _, ok := graph.NamedQueries[alias]; ok {
			t.Errorf("%q is an alias and should not be listed", alias)
		}
	}
	if strings.Contains(graph.NamedQueries["admin-identities"], "IAM") {
		t.Fatalf("admin-identities description = %q", graph.NamedQueries["admin-identities"])
	}
}

func TestPublicDatastoreIncludesS3AndGCS(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)
	if err := store.UpsertBatch(ctx, publicDatastoreFixture()); err != nil {
		t.Fatalf("upsert fixture: %v", err)
	}

	querier := graph.NewQuerier(store)
	for _, name := range []string{"public-datastore", "public-s3-buckets"} {
		t.Run(name, func(t *testing.T) {
			result, err := querier.Run(ctx, name)
			if err != nil {
				t.Fatalf("Run(%q): %v", name, err)
			}
			if result.Query != name {
				t.Fatalf("Query = %q, want %q", result.Query, name)
			}
			got := pathStartIDs(result)
			if !sameIDs(got, []string{s3PublicID, gcsPublicID}) {
				t.Fatalf("paths start at %v, want public S3 and GCS only", got)
			}
		})
	}

	for _, name := range []string{"admin-to-public-datastore", "toxic-s3-public-with-admin-role"} {
		t.Run(name, func(t *testing.T) {
			result, err := querier.Run(ctx, name)
			if err != nil {
				t.Fatalf("Run(%q): %v", name, err)
			}
			if result.Query != name {
				t.Fatalf("Query = %q, want %q", result.Query, name)
			}
			got := pathStartIDs(result)
			if !sameIDs(got, []string{s3PublicID, gcsPublicID}) {
				t.Fatalf("paths start at %v, want public S3 and GCS only", got)
			}
		})
	}

	admins, err := querier.Run(ctx, "admin-identities")
	if err != nil {
		t.Fatalf("Run(admin-identities): %v", err)
	}
	if !sameIDs(pathStartIDs(admins), []string{ownerID}) {
		t.Fatalf("admin identities = %v, want only %s", pathStartIDs(admins), ownerID)
	}
}

const (
	s3PublicID  = "aws:111111111111:global:datastore:public-logs"
	gcsPublicID = "gcp:demo:us-central1:datastore:public-assets"
	s3PrivateID = "aws:111111111111:global:datastore:private-data"
	ownerID     = "azure:00000000-0000-0000-0000-000000000000:global:identity:owner"
	readerID    = "aws:111111111111:global:identity:admin-reader"
)

func publicDatastoreFixture() graph.Batch {
	access := func(target string) graph.Edge {
		return graph.Edge{
			ID:       ownerID + "|" + target + "|" + graph.EdgeCanAccess,
			SourceID: ownerID,
			TargetID: target,
			Type:     graph.EdgeCanAccess,
		}
	}
	return graph.Batch{
		Nodes: []graph.Node{
			{
				ID: s3PublicID, Type: graph.NodeDatastore, Name: "public-logs", Provider: "aws",
				Properties: map[string]any{"public_access": true, "service": "s3"},
			},
			{
				ID: gcsPublicID, Type: graph.NodeDatastore, Name: "public-assets", Provider: "gcp",
				Properties: map[string]any{"public_access": true, "service": "gcs"},
			},
			{
				ID: s3PrivateID, Type: graph.NodeDatastore, Name: "private-data", Provider: "aws",
				Properties: map[string]any{"public_access": false, "service": "s3"},
			},
			{
				ID: ownerID, Type: graph.NodeIdentity, Name: "Owner", Provider: "azure",
				Properties: map[string]any{"admin_access": true},
			},
			{
				ID: readerID, Type: graph.NodeIdentity, Name: "admin-reader", Provider: "aws",
				Properties: map[string]any{"admin_access": false},
			},
		},
		Edges: []graph.Edge{
			access(s3PublicID),
			access(gcsPublicID),
			access(s3PrivateID),
		},
	}
}

func openQueryFixture(t *testing.T) *graph.Store {
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
	dbName := "omq" + hex.EncodeToString(raw[:])
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

	if err := migrate.Run(ctx, databaseURL.String(), migrationsDir(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store, err := graph.NewStore(ctx, databaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func pathStartIDs(result graph.PathResult) []string {
	ids := make([]string, 0, len(result.Paths))
	for _, path := range result.Paths {
		if len(path) == 0 {
			continue
		}
		ids = append(ids, path[0].ID)
	}
	return ids
}

func sameIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, id := range got {
		seen[id]++
	}
	for _, id := range want {
		seen[id]--
		if seen[id] < 0 {
			return false
		}
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
