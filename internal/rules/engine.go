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

var BuiltinCatalog = []Rule{
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

// Catalog is builtin graph-context rules plus embedded YAML packs.
var Catalog []Rule

func init() {
	Catalog = append([]Rule{}, BuiltinCatalog...)
	extra, err := LoadEmbeddedPacks()
	if err != nil {
		panic(err)
	}
	Catalog = append(Catalog, extra...)
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
		written, err := e.persistMatches(ctx, rule, matches)
		if err != nil {
			return result, err
		}
		result.FindingsCreated += written
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
		written, err := e.persistMatches(ctx, rule, matches)
		if err != nil {
			return result, err
		}
		result.FindingsCreated = written
		result.Matches = matches
		return result, nil
	}
	return result, fmt.Errorf("unknown rule %q", ruleID)
}

func (e *Engine) persistMatches(ctx context.Context, rule Rule, matches []Match) (int, error) {
	keep := make([]string, 0, len(matches))
	for _, match := range matches {
		findingID := findingNodeID(rule.ID, match.Resource.ID)
		if err := e.persistFinding(ctx, rule, match, findingID); err != nil {
			return 0, err
		}
		keep = append(keep, findingID)
	}
	if err := e.store.DeleteStaleRuleFindings(ctx, rule.ID, keep); err != nil {
		return 0, err
	}
	return len(matches), nil
}

func findingNodeID(ruleID, resourceID string) string {
	return fmt.Sprintf("finding:%s:%s", ruleID, resourceID)
}

func (e *Engine) persistFinding(ctx context.Context, rule Rule, match Match, findingID string) error {
	score := match.Context.ScoreBoost(match.BaseScore)
	description := match.Description
	if reason := match.Context.RankReason(); reason != "" {
		description += " " + reason
	}
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
					"finding_type":      "cspm",
					"rule_id":           rule.ID,
					"title":             match.Title,
					"description":       description,
					"severity":          SeverityFromScore(score),
					"normalized_score":  score,
					"graph_context":     match.Context,
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
	var matches []Match
	err := store.ForEachNode(ctx, graph.NodeDatastore, func(node graph.Node) error {
		public, _ := node.Properties["public_access"].(bool)
		if !public {
			return nil
		}
		gctx, err := loadGraphContext(ctx, store, node.ID)
		if err != nil {
			return err
		}
		matches = append(matches, Match{
			RuleID:      "cspm-public-datastore",
			Resource:    node,
			Title:       fmt.Sprintf("Public datastore: %s", node.Name),
			Description: "Datastore has public access indicators",
			BaseScore:   70,
			Context:     gctx,
		})
		return nil
	})
	if err != nil {
		return nil, err
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
	internet, err := store.ReachableFromInternet(ctx, nodeID)
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
