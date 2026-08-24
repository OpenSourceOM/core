// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package severity_test

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/enrichment/severity"
)

func TestFromCVSS(t *testing.T) {
	level, score := severity.FromCVSS(9.8)
	if level != severity.LevelCritical || score != 95 {
		t.Fatalf("FromCVSS(9.8) = (%s, %d)", level, score)
	}

	level, _ = severity.FromCVSS(7.2)
	if level != severity.LevelHigh {
		t.Fatalf("expected high, got %s", level)
	}
}

func TestFromLabel(t *testing.T) {
	if severity.FromLabel("MODERATE") != severity.LevelMedium {
		t.Fatal("expected medium severity")
	}
}
