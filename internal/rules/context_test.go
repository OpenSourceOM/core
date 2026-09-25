// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/rules"
)

func TestGraphContextScoreBoost(t *testing.T) {
	ctx := rules.GraphContext{
		InternetReachable: true,
		PathToDatastore:   true,
		AdminCanAccess:    true,
	}
	got := ctx.ScoreBoost(60)
	if got != 100 {
		t.Fatalf("ScoreBoost(60) = %d, want 100", got)
	}
}

func TestRankReasonPrefersDatastorePath(t *testing.T) {
	onPath := rules.GraphContext{InternetReachable: true, PathToDatastore: true}
	if onPath.RankReason() == "" {
		t.Fatal("expected a path reason")
	}
	exposed := rules.GraphContext{InternetReachable: true}
	if exposed.RankReason() == onPath.RankReason() {
		t.Fatal("an exposure with no datastore path needs a different reason")
	}
}

func TestSeverityFromScore(t *testing.T) {
	if rules.SeverityFromScore(95) != "critical" {
		t.Fatal("expected critical severity")
	}
}
