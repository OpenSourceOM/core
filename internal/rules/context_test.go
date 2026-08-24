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
	if got != 90 {
		t.Fatalf("ScoreBoost(60) = %d, want 90", got)
	}
}

func TestSeverityFromScore(t *testing.T) {
	if rules.SeverityFromScore(95) != "critical" {
		t.Fatal("expected critical severity")
	}
}
