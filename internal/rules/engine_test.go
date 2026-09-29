// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/migrate"
	"github.com/OpenSourceOM/core/internal/rules"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunDropsStaleFindingAndKeepsOthers(t *testing.T) {
	ctx := context.Background()
	store := openRulesFixture(t)

	const (
		account = "111122223333"
		public  = "aws:111122223333:global:datastore:public-logs"
		private = "aws:111122223333:global:datastore:private-data"
	)
	staleID := "finding:cspm-public-datastore:" + private
	cveID := "finding:cve-2021-44228:" + public
	otherID := "finding:cspm-internet-workload:" + public

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID: public, Type: graph.NodeDatastore, Name: "public-logs", Provider: "aws", AccountID: account,
				Properties: map[string]any{"public_access": true},
			},
			{
				ID: private, Type: graph.NodeDatastore, Name: "private-data", Provider: "aws", AccountID: account,
				Properties: map[string]any{"public_access": false},
			},
			{
				ID: staleID, Type: graph.NodeFinding, Name: "Public datastore", Provider: "aws", AccountID: account,
				Properties: map[string]any{
					"finding_type":      "cspm",
					"rule_id":           "cspm-public-datastore",
					"affected_resource": private,
				},
			},
			{
				ID: cveID, Type: graph.NodeFinding, Name: "CVE-2021-44228", Provider: "aws", AccountID: account,
				Properties: map[string]any{
					"finding_type":      "cve",
					"cve_id":            "CVE-2021-44228",
					"affected_resource": public,
				},
			},
			{
				ID: otherID, Type: graph.NodeFinding, Name: "Internet-exposed workload", Provider: "aws", AccountID: account,
				Properties: map[string]any{
					"finding_type":      "cspm",
					"rule_id":           "cspm-internet-workload",
					"affected_resource": public,
				},
			},
		},
		Edges: []graph.Edge{
			{ID: staleID + "|" + private + "|VIOLATES", SourceID: staleID, TargetID: private, Type: graph.EdgeViolates},
			{ID: cveID + "|" + public + "|VIOLATES", SourceID: cveID, TargetID: public, Type: graph.EdgeViolates},
			{ID: otherID + "|" + public + "|VIOLATES", SourceID: otherID, TargetID: public, Type: graph.EdgeViolates},
		},
	}
	if err := store.UpsertBatch(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}

	result, err := rules.NewEngine(store).Run(ctx, "cspm-public-datastore")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.FindingsCreated != 1 {
		t.Fatalf("FindingsCreated = %d, want 1", result.FindingsCreated)
	}

	requireRuleNode(t, ctx, store, "finding:cspm-public-datastore:"+public, true)
	requireRuleNode(t, ctx, store, staleID, false)
	requireRuleNode(t, ctx, store, cveID, true)
	requireRuleNode(t, ctx, store, otherID, true)
}

func TestRulesPagePastTheFirstPage(t *testing.T) {
	ctx := context.Background()
	store := openRulesFixture(t)

	const (
		account  = "111122223333"
		publicID = "aws:111122223333:global:datastore:public-last"
	)
	nodes := make([]graph.Node, 0, graph.MaxNodePageSize+1)
	for i := 0; i < graph.MaxNodePageSize; i++ {
		nodes = append(nodes, graph.Node{
			ID:         fmt.Sprintf("aws:111122223333:global:datastore:n-%04d", i),
			Type:       graph.NodeDatastore,
			Name:       fmt.Sprintf("n-%04d", i),
			Provider:   "aws",
			AccountID:  account,
			Properties: map[string]any{"public_access": false},
		})
	}
	nodes = append(nodes, graph.Node{
		ID:         publicID,
		Type:       graph.NodeDatastore,
		Name:       "zzz-public",
		Provider:   "aws",
		AccountID:  account,
		Properties: map[string]any{"public_access": true},
	})
	if err := store.UpsertBatch(ctx, graph.Batch{Nodes: nodes}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, ruleID := range []string{"cspm-public-datastore", "cis-s3-public-access"} {
		t.Run(ruleID, func(t *testing.T) {
			result, err := rules.NewEngine(store).Run(ctx, ruleID)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if result.FindingsCreated != 1 {
				t.Fatalf("FindingsCreated = %d, want the datastore past the first page", result.FindingsCreated)
			}
			requireRuleNode(t, ctx, store, "finding:"+ruleID+":"+publicID, true)
		})
	}
}

func requireRuleNode(t *testing.T, ctx context.Context, store *graph.Store, id string, want bool) {
	t.Helper()
	var exists bool
	if err := store.Pool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1)`, id).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("node %s exists=%v, want %v", id, exists, want)
	}
}

func openRulesFixture(t *testing.T) *graph.Store {
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
	dbName := "omr" + hex.EncodeToString(raw[:])
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
	store, err := graph.NewStore(ctx, databaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}
