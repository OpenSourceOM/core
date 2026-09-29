// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
)

const (
	attackPathRuleID       = "attack-path"
	attackPathDefaultScore = 75
)

// attackPathRule runs last. RunAll persists earlier rules first, so this
// pass sees findings those rules just wrote as well as CVE and exposure
// findings already on the graph.
var attackPathRule = Rule{
	ID:          attackPathRuleID,
	Name:        "Attack path",
	Description: "Internet-reachable workload with a finding on a path to a datastore",
	BaseScore:   attackPathDefaultScore,
	Run:         ruleAttackPath,
}

func ruleAttackPath(ctx context.Context, store *graph.Store) ([]Match, error) {
	combos, err := store.ListAttackPathCombinations(ctx)
	if err != nil {
		return nil, err
	}
	matches := make([]Match, 0, len(combos))
	for _, combo := range combos {
		score, ok := findingScore(combo.Finding.Properties)
		if !ok {
			score = attackPathDefaultScore
		}
		source := strings.TrimSpace(combo.Finding.Name)
		if title, ok := combo.Finding.Properties["title"].(string); ok && strings.TrimSpace(title) != "" {
			source = strings.TrimSpace(title)
		}
		matches = append(matches, Match{
			RuleID:          attackPathRuleID,
			Resource:        combo.Workload,
			Title:           fmt.Sprintf("Attack path: %s to %s", combo.Workload.Name, combo.Datastore.Name),
			Description:     fmt.Sprintf("%s is on a path to %s.", source, combo.Datastore.Name),
			BaseScore:       score,
			Path:            combo.Path,
			SourceFindingID: combo.Finding.ID,
			DatastoreID:     combo.Datastore.ID,
		})
	}
	return matches, nil
}

func (e *Engine) persistAttackPathMatches(ctx context.Context, rule Rule, matches []Match) (int, error) {
	keep := make([]string, 0, len(matches))
	for _, match := range matches {
		if match.SourceFindingID == "" || match.DatastoreID == "" {
			return 0, fmt.Errorf("attack path match missing source finding or datastore")
		}
		findingID := attackPathFindingID(match.SourceFindingID, match.DatastoreID)
		if err := e.persistAttackPathFinding(ctx, rule, match, findingID); err != nil {
			return 0, err
		}
		keep = append(keep, findingID)
	}
	if err := e.store.DeleteStaleRuleFindings(ctx, rule.ID, keep); err != nil {
		return 0, err
	}
	return len(matches), nil
}

func attackPathFindingID(sourceFindingID, datastoreID string) string {
	return fmt.Sprintf("finding:%s:%s:%s", attackPathRuleID, sourceFindingID, datastoreID)
}

func (e *Engine) persistAttackPathFinding(ctx context.Context, rule Rule, match Match, findingID string) error {
	score := match.BaseScore
	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:        findingID,
				Type:      graph.NodeFinding,
				Name:      rule.Name,
				Provider:  match.Resource.Provider,
				Region:    match.Resource.Region,
				AccountID: match.Resource.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"finding_type":      graph.FindingTypeAttackPath,
					"rule_id":           rule.ID,
					"title":             match.Title,
					"description":       match.Description,
					"severity":          SeverityFromScore(score),
					"normalized_score":  score,
					"affected_resource": match.Resource.ID,
					"source_finding_id": match.SourceFindingID,
					"datastore_id":      match.DatastoreID,
					"path":              match.Path,
				}),
			},
		},
		Edges: []graph.Edge{
			{
				ID:       fmt.Sprintf("%s|%s|%s", findingID, match.Resource.ID, graph.EdgeViolates),
				SourceID: findingID,
				TargetID: match.Resource.ID,
				Type:     graph.EdgeViolates,
			},
		},
	}
	return e.store.UpsertBatch(ctx, batch)
}

func findingScore(props map[string]any) (int, bool) {
	if props == nil {
		return 0, false
	}
	switch v := props["normalized_score"].(type) {
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			f, ferr := v.Float64()
			if ferr != nil {
				return 0, false
			}
			return int(f), true
		}
		return int(n), true
	default:
		return 0, false
	}
}
