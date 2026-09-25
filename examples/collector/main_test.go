// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/OpenSourceOM/core/sdk/collector"
)

func TestSampleBatch(t *testing.T) {
	batch := collector.Normalize(Sample())
	if err := collector.Validate(batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Nodes) != 3 || len(batch.Edges) != 2 {
		t.Fatalf("batch nodes=%d edges=%d", len(batch.Nodes), len(batch.Edges))
	}
}
