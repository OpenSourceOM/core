// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	"github.com/OpenSourceOM/core/internal/graph"
)

func packRunner(spec PackRule) func(context.Context, *graph.Store) ([]Match, error) {
	return func(ctx context.Context, store *graph.Store) ([]Match, error) {
		return runPackRule(ctx, store, spec)
	}
}

func runPackRule(ctx context.Context, store *graph.Store, spec PackRule) ([]Match, error) {
	nodes, err := store.ListNodes(ctx, spec.ResourceType, 500)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, node := range nodes {
		if !matchProperties(node.Properties, spec.Match.Properties) {
			continue
		}
		gctx, err := loadGraphContext(ctx, store, node.ID)
		if err != nil {
			return nil, err
		}
		if !matchGraph(gctx, spec.Match.Graph) {
			continue
		}
		matches = append(matches, Match{
			RuleID:      spec.ID,
			Resource:    node,
			Title:       fmt.Sprintf("%s: %s", spec.Name, node.Name),
			Description: spec.Description,
			BaseScore:   spec.BaseScore,
			Context:     gctx,
		})
	}
	return matches, nil
}

func matchProperties(have map[string]any, want map[string]any) bool {
	if len(want) == 0 {
		return true
	}
	if have == nil {
		return false
	}
	for key, expected := range want {
		if !valuesEqual(have[key], expected) {
			return false
		}
	}
	return true
}

func matchGraph(got GraphContext, want *GraphMatch) bool {
	if want == nil {
		return true
	}
	if want.InternetReachable != nil && got.InternetReachable != *want.InternetReachable {
		return false
	}
	if want.PathToDatastore != nil && got.PathToDatastore != *want.PathToDatastore {
		return false
	}
	if want.AdminCanAccess != nil && got.AdminCanAccess != *want.AdminCanAccess {
		return false
	}
	return true
}

func valuesEqual(have, want any) bool {
	if have == nil {
		return false
	}
	if hb, ok := asBool(have); ok {
		if wb, ok := asBool(want); ok {
			return hb == wb
		}
	}
	if reflect.DeepEqual(fmt.Sprint(have), fmt.Sprint(want)) {
		return true
	}
	return fmt.Sprint(have) == fmt.Sprint(want)
}

func asBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(t)
		return b, err == nil
	default:
		return false, false
	}
}
