// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"github.com/OpenSourceOM/core/internal/graph"
)

type Match struct {
	RuleID      string       `json:"rule_id"`
	Resource    graph.Node   `json:"resource"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	BaseScore   int          `json:"base_score"`
	Context     GraphContext `json:"graph_context"`
}

type Rule struct {
	ID          string
	Name        string
	Description string
	BaseScore   int
	Run         func(ctx context.Context, store *graph.Store) ([]Match, error)
}

var Catalog = []Rule{
	{
		ID:          "cspm-public-datastore",
		Name:        "Public datastore",
		Description: "Datastore flagged as publicly accessible",
		BaseScore:   70,
		Run:         rulePublicDatastore,
	},
	{
		ID:          "cspm-internet-workload",
		Name:        "Internet-exposed workload",
		Description: "Workload reachable from the internet",
		BaseScore:   65,
		Run:         ruleInternetWorkload,
	},
	{
		ID:          "cspm-admin-datastore-access",
		Name:        "Admin identity can access datastore",
		Description: "Identity with admin indicators has access to a datastore",
		BaseScore:   60,
		Run:         ruleAdminDatastoreAccess,
	},
}

func CatalogMap() map[string]string {
	out := make(map[string]string, len(Catalog))
	for _, rule := range Catalog {
		out[rule.ID] = rule.Description
	}
	return out
}

type Engine struct {
	store *graph.Store
}

type RunResult struct {
	Matches         []Match `json:"matches"`
	FindingsCreated int     `json:"findings_created"`
}

func NewEngine(store *graph.Store) *Engine {
	return &Engine{store: store}
}

func (e *Engine) RunAll(ctx context.Context) (RunResult, error) {
	var result RunResult
	for _, rule := range Catalog {
		matches, err := rule.Run(ctx, e.store)
		if err != nil {
			return result, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		for _, match := range matches {
			if err := e.persistFinding(ctx, rule, match); err != nil {
				return result, err
			}
			result.FindingsCreated++
		}
		result.Matches = append(result.Matches, matches...)
	}
	return result, nil
}

func (e *Engine) Run(ctx context.Context, ruleID string) (RunResult, error) {
	var result RunResult
	for _, rule := range Catalog {
		if rule.ID != ruleID {
			continue
		}
		matches, err := rule.Run(ctx, e.store)
		if err != nil {
			return result, err
		}
		for _, match := range matches {
			if err := e.persistFinding(ctx, rule, match); err != nil {
				return result, err
			}
			result.FindingsCreated++
		}
		result.Matches = matches
		return result, nil
	}
	return result, fmt.Errorf("unknown rule %q", ruleID)
}

func (e *Engine) persistFinding(ctx context.Context, rule Rule, match Match) error {
	score := match.Context.ScoreBoost(match.BaseScore)
	findingID := fmt.Sprintf("finding:%s:%s", rule.ID, match.Resource.ID)

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
					"finding_type":     "cspm",
					"rule_id":          rule.ID,
					"title":            match.Title,
					"description":      match.Description,
					"severity":         SeverityFromScore(score),
					"normalized_score": score,
					"graph_context":    match.Context,
					"affected_resource": match.Resource.ID,
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

func rulePublicDatastore(ctx context.Context, store *graph.Store) ([]Match, error) {
	nodes, err := store.ListNodes(ctx, graph.NodeDatastore, 500)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, node := range nodes {
		public, _ := node.Properties["public_access"].(bool)
		if !public {
			continue
		}
		gctx, err := loadGraphContext(ctx, store, node.ID)
		if err != nil {
			return nil, err
		}
		matches = append(matches, Match{
			RuleID:      "cspm-public-datastore",
			Resource:    node,
			Title:       fmt.Sprintf("Public datastore: %s", node.Name),
			Description: "Datastore has public access indicators",
			BaseScore:   70,
			Context:     gctx,
		})
	}
	return matches, nil
}

func ruleInternetWorkload(ctx context.Context, store *graph.Store) ([]Match, error) {
	ids, err := store.InternetReachableWorkloadIDs(ctx)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, id := range ids {
		node, err := store.GetNode(ctx, id)
		if err != nil {
			return nil, err
		}
		gctx, err := loadGraphContext(ctx, store, node.ID)
		if err != nil {
			return nil, err
		}
		matches = append(matches, Match{
			RuleID:      "cspm-internet-workload",
			Resource:    node,
			Title:       fmt.Sprintf("Internet-exposed workload: %s", node.Name),
			Description: "Workload is reachable from the internet",
			BaseScore:   65,
			Context:     gctx,
		})
	}
	return matches, nil
}

func ruleAdminDatastoreAccess(ctx context.Context, store *graph.Store) ([]Match, error) {
	pairs, err := store.ListAdminDatastorePairs(ctx)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, row := range pairs {
		gctx, err := loadGraphContext(ctx, store, row.Datastore.ID)
		if err != nil {
			return nil, err
		}
		gctx.AdminCanAccess = true
		matches = append(matches, Match{
			RuleID:      "cspm-admin-datastore-access",
			Resource:    row.Datastore,
			Title:       fmt.Sprintf("Admin access to datastore: %s", row.Datastore.Name),
			Description: fmt.Sprintf("Identity %s can access datastore %s", row.Identity.Name, row.Datastore.Name),
			BaseScore:   60,
			Context:     gctx,
		})
	}
	return matches, nil
}

func loadGraphContext(ctx context.Context, store *graph.Store, nodeID string) (GraphContext, error) {
	internet, err := store.HasIncomingEdge(ctx, graph.InternetNodeID, nodeID, graph.EdgeReachable)
	if err != nil {
		return GraphContext{}, err
	}
	pathToDS, err := store.OnInternetDatastorePath(ctx, nodeID)
	if err != nil {
		return GraphContext{}, err
	}
	return GraphContext{
		InternetReachable: internet,
		PathToDatastore:   pathToDS,
	}, nil
}
