// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	for _, name := range []string{"public-datastore", "admin-to-public-datastore", "admin-identities", "internet-to-sensitive-datastore"} {
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

func TestInternetToDatastoreIncludesManagedDatabase(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)
	if err := store.UpsertBatch(ctx, managedDatabaseFixture()); err != nil {
		t.Fatalf("upsert fixture: %v", err)
	}

	result, err := graph.NewQuerier(store).Run(ctx, "internet-to-datastore")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %d, want the one managed-database path", len(result.Paths))
	}
	if result.Truncated {
		t.Fatalf("Truncated = true (%s), want a complete result", result.Truncation)
	}
	var got []string
	for _, node := range result.Paths[0] {
		got = append(got, node.ID)
	}
	want := []string{graph.InternetNodeID, rdsWorkloadID, rdsDatastoreID}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("path = %v, want %v", got, want)
	}
}

func TestInternetToSensitiveDatastoreKeepsMarkedStores(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)
	if err := store.UpsertBatch(ctx, sensitivityFixture()); err != nil {
		t.Fatalf("upsert fixture: %v", err)
	}

	querier := graph.NewQuerier(store)
	all, err := querier.Run(ctx, "internet-to-datastore")
	if err != nil {
		t.Fatalf("Run(internet-to-datastore): %v", err)
	}
	if !sameIDs(pathEndIDs(all), []string{markedDatastoreID, unmarkedDatastoreID, blankDatastoreID}) {
		t.Fatalf("unfiltered ends = %v, want marked, unmarked, and blank", pathEndIDs(all))
	}

	marked, err := querier.Run(ctx, "internet-to-sensitive-datastore")
	if err != nil {
		t.Fatalf("Run(internet-to-sensitive-datastore): %v", err)
	}
	if marked.Query != "internet-to-sensitive-datastore" {
		t.Fatalf("Query = %q", marked.Query)
	}
	if !sameIDs(pathEndIDs(marked), []string{markedDatastoreID}) {
		t.Fatalf("sensitive ends = %v, want only the marked datastore", pathEndIDs(marked))
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
	s3PublicID          = "aws:111111111111:global:datastore:public-logs"
	gcsPublicID         = "gcp:demo:us-central1:datastore:public-assets"
	s3PrivateID         = "aws:111111111111:global:datastore:private-data"
	ownerID             = "azure:00000000-0000-0000-0000-000000000000:global:identity:owner"
	readerID            = "aws:111111111111:global:identity:admin-reader"
	rdsWorkloadID       = "aws:111122223333:us-east-1:workload:i-web"
	rdsDatastoreID      = "aws:111122223333:us-east-1:datastore:prod"
	rdsIsolatedID       = "aws:111122223333:us-east-1:datastore:isolated"
	sensitiveWorkloadID = "aws:111122223333:us-east-1:workload:web"
	markedDatastoreID   = "aws:111122223333:us-east-1:datastore:customers"
	unmarkedDatastoreID = "aws:111122223333:us-east-1:datastore:logs"
	blankDatastoreID    = "aws:111122223333:us-east-1:datastore:blank"
	directDatastoreID   = "aws:111122223333:us-east-1:datastore:direct"
)

func managedDatabaseFixture() graph.Batch {
	p := graph.MustProperties
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + typ, SourceID: src, TargetID: dst, Type: typ}
	}
	return graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: rdsWorkloadID, Type: graph.NodeWorkload, Name: "web", Provider: "aws"},
			{
				ID: rdsDatastoreID, Type: graph.NodeDatastore, Name: "prod", Provider: "aws",
				Properties: p(map[string]any{"service": "rds", "public_access": false, "engine": "postgres"}),
			},
			{
				ID: rdsIsolatedID, Type: graph.NodeDatastore, Name: "isolated", Provider: "aws",
				Properties: p(map[string]any{"service": "rds", "public_access": true, "engine": "postgres"}),
			},
			{
				ID: s3PublicID, Type: graph.NodeDatastore, Name: "public-logs", Provider: "aws",
				Properties: p(map[string]any{"service": "s3", "public_access": true}),
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, rdsWorkloadID, graph.EdgeReachable),
			edge(rdsWorkloadID, rdsDatastoreID, graph.EdgeCanAccess),
			edge(graph.InternetNodeID, s3PublicID, graph.EdgeReachable),
		},
	}
}

func sensitivityFixture() graph.Batch {
	p := graph.MustProperties
	edge := func(src, dst string) graph.Edge {
		return graph.Edge{ID: src + "|" + dst + "|" + graph.EdgeCanAccess, SourceID: src, TargetID: dst, Type: graph.EdgeCanAccess}
	}
	reach := graph.Edge{
		ID:       graph.InternetNodeID + "|" + sensitiveWorkloadID + "|" + graph.EdgeReachable,
		SourceID: graph.InternetNodeID,
		TargetID: sensitiveWorkloadID,
		Type:     graph.EdgeReachable,
	}
	direct := graph.Edge{
		ID:       graph.InternetNodeID + "|" + directDatastoreID + "|" + graph.EdgeReachable,
		SourceID: graph.InternetNodeID,
		TargetID: directDatastoreID,
		Type:     graph.EdgeReachable,
	}
	return graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: sensitiveWorkloadID, Type: graph.NodeWorkload, Name: "web", Provider: "aws"},
			{
				ID: markedDatastoreID, Type: graph.NodeDatastore, Name: "customers", Provider: "aws",
				Properties: p(map[string]any{"service": "s3", "sensitivity": "customer"}),
			},
			{
				ID: unmarkedDatastoreID, Type: graph.NodeDatastore, Name: "logs", Provider: "aws",
				Properties: p(map[string]any{"service": "s3"}),
			},
			{
				ID: blankDatastoreID, Type: graph.NodeDatastore, Name: "blank", Provider: "aws",
				Properties: p(map[string]any{"service": "s3", "sensitivity": "  "}),
			},
			{
				ID: directDatastoreID, Type: graph.NodeDatastore, Name: "direct", Provider: "aws",
				Properties: p(map[string]any{"service": "s3", "sensitivity": "customer"}),
			},
		},
		Edges: []graph.Edge{
			reach,
			edge(sensitiveWorkloadID, markedDatastoreID),
			edge(sensitiveWorkloadID, unmarkedDatastoreID),
			edge(sensitiveWorkloadID, blankDatastoreID),
			direct,
		},
	}
}

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

func TestInternetToWorkloadReportsPathCap(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const pathCap = 50
	nodes := []graph.Node{{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"}}
	edges := make([]graph.Edge, 0, pathCap+1)
	for i := 0; i < pathCap+1; i++ {
		id := fmt.Sprintf("aws:111:us-east-1:workload:w-%03d", i)
		nodes = append(nodes, graph.Node{ID: id, Type: graph.NodeWorkload, Name: fmt.Sprintf("w-%03d", i), Provider: "aws"})
		edges = append(edges, graph.Edge{
			ID:       graph.InternetNodeID + "|" + id + "|" + graph.EdgeReachable,
			SourceID: graph.InternetNodeID,
			TargetID: id,
			Type:     graph.EdgeReachable,
		})
	}
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes, Edges: edges}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	result, err := graph.NewQuerier(store).Run(ctx, "internet-to-workload")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Paths) != pathCap {
		t.Fatalf("paths = %d, want the cap %d", len(result.Paths), pathCap)
	}
	if !result.Truncated || result.Truncation != "path cap" {
		t.Fatalf("truncation = %v %q, want path cap", result.Truncated, result.Truncation)
	}
}

func TestInternetToWorkloadReportsDepthCap(t *testing.T) {
	ctx := context.Background()
	store := openQueryFixture(t)

	const near = "aws:111:us-east-1:workload:near"
	const deep = "aws:111:us-east-1:workload:deep"
	nodes := []graph.Node{
		{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
		{ID: near, Type: graph.NodeWorkload, Name: "near", Provider: "aws"},
		{ID: deep, Type: graph.NodeWorkload, Name: "deep", Provider: "aws"},
	}
	edges := []graph.Edge{{
		ID:       graph.InternetNodeID + "|" + near + "|" + graph.EdgeReachable,
		SourceID: graph.InternetNodeID,
		TargetID: near,
		Type:     graph.EdgeReachable,
	}}
	const depthCap = 6
	prev := graph.InternetNodeID
	for i := 1; i <= depthCap; i++ {
		id := fmt.Sprintf("aws:111:us-east-1:network:hop-%d", i)
		nodes = append(nodes, graph.Node{ID: id, Type: graph.NodeNetwork, Name: fmt.Sprintf("hop-%d", i), Provider: "aws"})
		edges = append(edges, graph.Edge{
			ID:       prev + "|" + id + "|" + graph.EdgeReachable,
			SourceID: prev,
			TargetID: id,
			Type:     graph.EdgeReachable,
		})
		prev = id
	}
	edges = append(edges, graph.Edge{
		ID:       prev + "|" + deep + "|" + graph.EdgeReachable,
		SourceID: prev,
		TargetID: deep,
		Type:     graph.EdgeReachable,
	})
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes, Edges: edges}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	result, err := graph.NewQuerier(store).Run(ctx, "internet-to-workload")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Truncated || result.Truncation != "depth cap" {
		t.Fatalf("truncation = %v %q, want depth cap", result.Truncated, result.Truncation)
	}
	var sawNear, sawDeep bool
	for _, path := range result.Paths {
		for _, node := range path {
			if node.ID == near {
				sawNear = true
			}
			if node.ID == deep {
				sawDeep = true
			}
		}
	}
	if !sawNear || sawDeep {
		t.Fatalf("near=%v deep=%v, want the shallow workload only", sawNear, sawDeep)
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

func pathEndIDs(result graph.PathResult) []string {
	ids := make([]string, 0, len(result.Paths))
	for _, path := range result.Paths {
		if len(path) == 0 {
			continue
		}
		ids = append(ids, path[len(path)-1].ID)
	}
	return ids
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
