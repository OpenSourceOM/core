// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestEnrichAttachesOnlyMatchingCVE(t *testing.T) {
	web := graph.Node{
		ID: "aws:ec2:i-web-1", Type: graph.NodeWorkload, Name: "web-1", Provider: "aws",
		Properties: map[string]any{
			"public_ip": true,
			"packages":  []any{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
		},
	}
	worker := graph.Node{
		ID: "aws:ec2:i-worker-1", Type: graph.NodeWorkload, Name: "worker-1", Provider: "aws",
		Properties: map[string]any{
			"public_ip": false,
			"packages":  []any{"cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"},
		},
	}
	store := &memGraph{nodes: map[string]graph.Node{web.ID: web, worker.ID: worker}}
	source := scriptedSource{fn: func(inv Inventory, ids []string) ([]FindingCVE, error) {
		for _, pkg := range inv.Packages {
			if pkg.Version == "2.14.1" {
				return []FindingCVE{{
					ID: "CVE-2021-44228", Title: "log4j", Severity: "critical", Normalized: 95,
					CVSSScore: 10, Matched: pkg.Raw,
				}}, nil
			}
		}
		return nil, nil
	}}
	enricher := &Enricher{store: store, source: &source}

	result, err := enricher.EnrichCVE(context.Background(), Options{InternetOnly: false})
	if err != nil {
		t.Fatal(err)
	}
	if result.FindingsCreated != 2 {
		t.Fatalf("created = %d, want cve + exposure", result.FindingsCreated)
	}

	var cveOn, exposure, cveWorker int
	for _, batch := range store.batches {
		for _, node := range batch.Nodes {
			switch node.Properties["finding_type"] {
			case "cve":
				if node.Properties["affected_resource"] == web.ID {
					cveOn++
					if node.Properties["matched_identifier"] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
						t.Fatalf("matched = %#v", node.Properties["matched_identifier"])
					}
				}
				if node.Properties["affected_resource"] == worker.ID {
					cveWorker++
				}
			case "exposure":
				exposure++
			}
		}
	}
	if cveOn != 1 || exposure != 1 || cveWorker != 0 {
		t.Fatalf("cve web=%d exposure=%d cve worker=%d", cveOn, exposure, cveWorker)
	}
}

func TestEnrichExplicitCVEStillRequiresInventory(t *testing.T) {
	bare := graph.Node{
		ID: "aws:ec2:i-bare", Type: graph.NodeWorkload, Name: "bare",
		Properties: map[string]any{"public_ip": true},
	}
	store := &memGraph{
		nodes:     map[string]graph.Node{bare.ID: bare},
		reachable: []string{bare.ID},
	}
	source := scriptedSource{fn: func(Inventory, []string) ([]FindingCVE, error) {
		return nil, nil
	}}
	enricher := &Enricher{store: store, source: &source}
	result, err := enricher.EnrichCVE(context.Background(), Options{
		CVEIDs:       []string{"CVE-2021-44228"},
		InternetOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.FindingsCreated != 1 {
		t.Fatalf("created = %d, want exposure only", result.FindingsCreated)
	}
	if len(source.ids) != 1 || source.ids[0][0] != "CVE-2021-44228" {
		t.Fatalf("source ids = %#v", source.ids)
	}
}

func TestEnrichRejectsBadCVEID(t *testing.T) {
	enricher := &Enricher{store: &memGraph{}, source: &scriptedSource{}}
	_, err := enricher.EnrichCVE(context.Background(), Options{CVEIDs: []string{"log4shell"}})
	if err == nil {
		t.Fatal("expected an error")
	}
}

type scriptedSource struct {
	fn  func(Inventory, []string) ([]FindingCVE, error)
	ids [][]string
}

func (s *scriptedSource) Match(_ context.Context, inv Inventory, cveIDs []string) ([]FindingCVE, error) {
	s.ids = append(s.ids, append([]string(nil), cveIDs...))
	if s.fn == nil {
		return nil, nil
	}
	return s.fn(inv, cveIDs)
}

type memGraph struct {
	nodes     map[string]graph.Node
	reachable []string
	batches   []graph.Batch
}

func (m *memGraph) ForEachNode(_ context.Context, nodeType string, visit func(graph.Node) error) error {
	for _, node := range m.nodes {
		if nodeType != "" && node.Type != nodeType {
			continue
		}
		if err := visit(node); err != nil {
			return err
		}
	}
	return nil
}

func (m *memGraph) InternetReachableWorkloadIDs(context.Context) ([]string, error) {
	return m.reachable, nil
}

func (m *memGraph) GetNode(_ context.Context, id string) (graph.Node, error) {
	node, ok := m.nodes[id]
	if !ok {
		return graph.Node{}, errors.New("node not found")
	}
	return node, nil
}

func (m *memGraph) UpsertBatch(_ context.Context, batch graph.Batch) error {
	m.batches = append(m.batches, batch)
	return nil
}
