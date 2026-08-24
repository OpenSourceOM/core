// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/enrichment/nvd"
	"github.com/OpenSourceOM/core/internal/enrichment/severity"
	"github.com/OpenSourceOM/core/internal/graph"
)

type Enricher struct {
	store *graph.Store
	nvd   *nvd.Client
}

type Options struct {
	CVEIDs       []string
	InternetOnly bool
}

type Result struct {
	FindingsCreated int
	FindingsUpdated int
}

func New(store *graph.Store, nvdClient *nvd.Client) *Enricher {
	return &Enricher{store: store, nvd: nvdClient}
}

func (e *Enricher) EnrichCVE(ctx context.Context, opts Options) (Result, error) {
	var result Result
	targets, err := e.targetWorkloads(ctx, opts.InternetOnly)
	if err != nil {
		return result, err
	}
	if len(targets) == 0 {
		return result, nil
	}

	cveIDs := opts.CVEIDs
	if len(cveIDs) == 0 {
		cveIDs = []string{"CVE-2021-44228"}
	}

	for _, workload := range targets {
		for _, cveID := range cveIDs {
			created, err := e.attachCVE(ctx, workload, cveID)
			if err != nil {
				return result, fmt.Errorf("attach %s to %s: %w", cveID, workload.ID, err)
			}
			if created {
				result.FindingsCreated++
			} else {
				result.FindingsUpdated++
			}
		}

		if workloadHasPublicIP(workload) {
			created, err := e.attachExposureFinding(ctx, workload)
			if err != nil {
				return result, err
			}
			if created {
				result.FindingsCreated++
			} else {
				result.FindingsUpdated++
			}
		}
	}

	return result, nil
}

func (e *Enricher) targetWorkloads(ctx context.Context, internetOnly bool) ([]graph.Node, error) {
	if !internetOnly {
		return e.store.ListNodes(ctx, graph.NodeWorkload, 500)
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

func (e *Enricher) attachCVE(ctx context.Context, workload graph.Node, cveID string) (created bool, err error) {
	cve, err := e.nvd.Lookup(ctx, cveID)
	if err != nil {
		return false, err
	}

	findingID := fmt.Sprintf("finding:%s:%s", strings.ToLower(cve.ID), workload.ID)
	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:        findingID,
				Type:      graph.NodeFinding,
				Name:      cve.ID,
				Provider:  workload.Provider,
				Region:    workload.Region,
				AccountID: workload.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"cve_id":            cve.ID,
					"title":             cve.Title,
					"description":       cve.Description,
					"cvss_score":        cve.CVSSScore,
					"severity":          cve.Severity,
					"normalized_score":  cve.Normalized,
					"finding_type":      "cve",
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
				Properties: graph.MustProperties(map[string]any{
					"relationship": "affects",
				}),
			},
		},
	}

	if err := e.store.UpsertBatch(ctx, batch); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Enricher) attachExposureFinding(ctx context.Context, workload graph.Node) (created bool, err error) {
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
					"finding_type":     "exposure",
					"severity":         level,
					"normalized_score": normalized,
					"title":            "Workload reachable from the internet",
					"description":      "This workload has a path from the internet via network controls.",
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

	if err := e.store.UpsertBatch(ctx, batch); err != nil {
		return false, err
	}
	return true, nil
}

func workloadHasPublicIP(workload graph.Node) bool {
	ip, _ := workload.Properties["public_ip"].(string)
	return strings.TrimSpace(ip) != ""
}
