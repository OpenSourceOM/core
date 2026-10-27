// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"slices"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestUnionPackagesKeepsInstanceOnlyPackages(t *testing.T) {
	image := []string{"pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1"}
	instance := []string{
		"pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1",
		"pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14",
	}
	got := graph.UnionPackages(instance, image)
	want := []string{
		"pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14",
		"pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("instance packages = %#v", got)
	}

	sibling := graph.UnionPackages(nil, image)
	if slices.Contains(sibling, "pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14") {
		t.Fatalf("sibling received an instance package: %#v", sibling)
	}
	if !slices.Equal(sibling, image) {
		t.Fatalf("sibling = %#v", sibling)
	}
}
