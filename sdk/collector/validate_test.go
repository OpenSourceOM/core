// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestNormalizeAndValidate(t *testing.T) {
	batch := Normalize(Batch{
		Nodes: []Node{
			{ID: InternetNodeID, Type: NodeInternet, Name: "Internet"},
			{ID: "plugin:host:1", Type: NodeWorkload, Name: "edge"},
		},
		Edges: []Edge{{
			SourceID: InternetNodeID,
			TargetID: "plugin:host:1",
			Type:     EdgeReachable,
		}},
	})
	if batch.Edges[0].ID != InternetNodeID+"|plugin:host:1|"+EdgeReachable {
		t.Fatalf("edge id = %q", batch.Edges[0].ID)
	}
	if err := Validate(batch); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	base := Batch{
		Nodes: []Node{{ID: "plugin:host:1", Type: NodeWorkload, Name: "edge"}},
	}
	cases := []struct {
		name  string
		batch Batch
	}{
		{
			name:  "unknown type",
			batch: Batch{Nodes: []Node{{ID: "x", Type: "Bucket", Name: "b"}}},
		},
		{
			name: "duplicate node",
			batch: Batch{Nodes: []Node{
				{ID: "x", Type: NodeWorkload, Name: "a"},
				{ID: "x", Type: NodeWorkload, Name: "b"},
			}},
		},
		{
			name: "dangling edge",
			batch: Normalize(Batch{
				Nodes: base.Nodes,
				Edges: []Edge{{SourceID: "plugin:host:1", TargetID: "missing", Type: EdgeCanAccess}},
			}),
		},
		{
			name:  "missing name",
			batch: Batch{Nodes: []Node{{ID: "x", Type: NodeWorkload}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.batch); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestWriteBatch(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBatch(&buf, staticCollector{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"type":"Workload"`) {
		t.Fatalf("stdout = %s", buf.String())
	}
}

type staticCollector struct{}

func (staticCollector) Collect(context.Context) (Batch, error) {
	return Batch{
		Nodes: []Node{{ID: "plugin:host:1", Type: NodeWorkload, Name: "edge"}},
	}, nil
}
