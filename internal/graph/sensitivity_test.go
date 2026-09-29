// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestSensitivityFromTags(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]string
		want string
		ok   bool
	}{
		{name: "empty", tags: nil},
		{name: "unrelated", tags: map[string]string{"env": "prod"}},
		{name: "blank sensitivity", tags: map[string]string{"sensitivity": "  "}},
		{
			name: "data-class",
			tags: map[string]string{"data-class": " customer "},
			want: "customer",
			ok:   true,
		},
		{
			name: "sensitivity wins",
			tags: map[string]string{"data-class": "customer", "Sensitivity": "restricted"},
			want: "restricted",
			ok:   true,
		},
		{
			name: "blank sensitivity falls through",
			tags: map[string]string{"sensitivity": "", "Data-Class": "pii"},
			want: "pii",
			ok:   true,
		},
		{
			name: "exact key wins over a different case",
			tags: map[string]string{"Sensitivity": "high", "sensitivity": "customer"},
			want: "customer",
			ok:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := graph.SensitivityFromTags(tc.tags)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("SensitivityFromTags() = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestSetSensitivityLeavesUnmarkedPropsAlone(t *testing.T) {
	props := map[string]any{"service": "s3"}
	graph.SetSensitivity(props, map[string]string{"env": "prod"})
	if _, ok := props[graph.SensitivityProperty]; ok {
		t.Fatalf("unmarked props = %#v", props)
	}
	graph.SetSensitivity(props, map[string]string{"data-class": "customer"})
	if props[graph.SensitivityProperty] != "customer" {
		t.Fatalf("sensitivity = %#v", props[graph.SensitivityProperty])
	}
	graph.SetSensitivity(nil, map[string]string{"sensitivity": "customer"})
}
