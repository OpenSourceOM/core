// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
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

func TestNamedQueriesIncludesToxicS3(t *testing.T) {
	if _, ok := graph.NamedQueries["toxic-s3-public-with-admin-role"]; !ok {
		t.Fatal("expected toxic-s3-public-with-admin-role in NamedQueries")
	}
}
