// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/enrichment/severity"
	"github.com/OpenSourceOM/core/internal/graph"
)

type graphStore interface {
	ForEachNode(ctx context.Context, nodeType string, visit func(graph.Node) error) error
	InternetReachableWorkloadIDs(ctx context.Context) ([]string, error)
	GetNode(ctx context.Context, id string) (graph.Node, error)
	UpsertBatch(ctx context.Context, batch graph.Batch) error
}

type Enricher struct {
	store  graphStore
	source Source
}

type Options struct {
	CVEIDs       []string
	InternetOnly bool
}

type Result struct {
	FindingsCreated int
	FindingsUpdated int
}

func New(store *graph.Store, source Source) *Enricher {
	return &Enricher{store: store, source: source}
}

func (e *Enricher) EnrichCVE(ctx context.Context, opts Options) (Result, error) {
	var result Result
	cveIDs, err := normalizeCVEIDs(opts.CVEIDs)
	if err != nil {
		return result, err
	}
	targets, err := e.targetWorkloads(ctx, opts.InternetOnly)
	if err != nil {
		return result, err
	}
	if len(targets) == 0 {
		return result, nil
	}

	for _, workload := range targets {
		inv := ParseInventory(workload.Properties)
		hits, err := e.source.Match(ctx, inv, cveIDs)
		if err != nil {
			return result, fmt.Errorf("match %s: %w", workload.ID, err)
		}
		for _, hit := range hits {
			if err := e.attachCVE(ctx, workload, hit); err != nil {
				return result, fmt.Errorf("attach %s to %s: %w", hit.ID, workload.ID, err)
			}
			result.FindingsCreated++
		}

		if workloadHasPublicIP(workload) {
			if err := e.attachExposureFinding(ctx, workload); err != nil {
				return result, err
			}
			result.FindingsCreated++
		}
	}

	return result, nil
}

func (e *Enricher) targetWorkloads(ctx context.Context, internetOnly bool) ([]graph.Node, error) {
	if !internetOnly {
		var workloads []graph.Node
		err := e.store.ForEachNode(ctx, graph.NodeWorkload, func(node graph.Node) error {
			workloads = append(workloads, node)
			return nil
		})
		return workloads, err
	}

	ids, err := e.store.InternetReachableWorkloadIDs(ctx)
	if err != nil {
		return nil, err
	}
	var workloads []graph.Node
	for _, id := range ids {
		node, err := e.store.GetNode(ctx, id)
		if err != nil {
			return nil, err
		}
		workloads = append(workloads, node)
	}
	return workloads, nil
}

func (e *Enricher) attachCVE(ctx context.Context, workload graph.Node, hit FindingCVE) error {
	findingID := fmt.Sprintf("finding:%s:%s", strings.ToLower(hit.ID), workload.ID)
	props := map[string]any{
		"cve_id":            hit.ID,
		"title":             hit.Title,
		"description":       hit.Description,
		"cvss_score":        hit.CVSSScore,
		"severity":          hit.Severity,
		"normalized_score":  hit.Normalized,
		"finding_type":      "cve",
		"affected_resource": workload.ID,
	}
	if hit.Matched != "" {
		props["matched_identifier"] = hit.Matched
	}
	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:         findingID,
				Type:       graph.NodeFinding,
				Name:       hit.ID,
				Provider:   workload.Provider,
				Region:     workload.Region,
				AccountID:  workload.AccountID,
				Properties: graph.MustProperties(props),
			},
		},
		Edges: []graph.Edge{
			{
				ID:       fmt.Sprintf("%s|%s|%s", findingID, workload.ID, graph.EdgeViolates),
				SourceID: findingID,
				TargetID: workload.ID,
				Type:     graph.EdgeViolates,
				Properties: graph.MustProperties(map[string]any{
					"relationship": "affects",
				}),
			},
		},
	}
	return e.store.UpsertBatch(ctx, batch)
}

func (e *Enricher) attachExposureFinding(ctx context.Context, workload graph.Node) error {
	findingID := fmt.Sprintf("finding:internet-exposed:%s", workload.ID)
	level := severity.LevelHigh
	normalized := severity.NormalizedScore(level)

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:        findingID,
				Type:      graph.NodeFinding,
				Name:      "Internet-exposed workload",
				Provider:  workload.Provider,
				Region:    workload.Region,
				AccountID: workload.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"finding_type":      "exposure",
					"severity":          level,
					"normalized_score":  normalized,
					"title":             "Workload reachable from the internet",
					"description":       "This workload has a path from the internet via network controls.",
					"affected_resource": workload.ID,
				}),
			},
		},
		Edges: []graph.Edge{
			{
				ID:       fmt.Sprintf("%s|%s|%s", findingID, workload.ID, graph.EdgeViolates),
				SourceID: findingID,
				TargetID: workload.ID,
				Type:     graph.EdgeViolates,
			},
		},
	}
	return e.store.UpsertBatch(ctx, batch)
}

func workloadHasPublicIP(workload graph.Node) bool {
	switch v := workload.Properties["public_ip"].(type) {
	case bool:
		return v
	case string:
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	if ip, ok := workload.Properties["public_ip_address"].(string); ok {
		return strings.TrimSpace(ip) != ""
	}
	return false
}
