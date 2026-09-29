// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

func TestPathIDs(t *testing.T) {
	got := pathIDs(map[string]any{"path": []any{"internet:global", "web"}})
	if len(got) != 2 || got[0] != "internet:global" || got[1] != "web" {
		t.Fatalf("pathIDs = %#v", got)
	}
	if pathIDs(map[string]any{"path": []any{"web", 1}}) != nil {
		t.Fatal("mixed path should be dropped")
	}
	if pathIDs(map[string]any{}) != nil {
		t.Fatal("missing path should be empty")
	}
}
