// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidCursor is returned when a page cursor cannot be used for this list.
var ErrInvalidCursor = errors.New("invalid cursor")

const (
	cursorNodesOfType = "nodes"
	cursorAllNodes    = "all_nodes"
	cursorEdges       = "edges"
	cursorFindings    = "findings"
)

// pageCursor is the keyset position of the last row on a page.
// Score uses -1 when a finding has no normalized_score, which sorts after
// every real score (scores are non-negative).
type pageCursor struct {
	Kind     string  `json:"k"`
	Type     string  `json:"t,omitempty"`
	Name     string  `json:"n,omitempty"`
	ID       string  `json:"i"`
	SourceID string  `json:"s,omitempty"`
	Score    float64 `json:"sc,omitempty"`
}

// ForEachNode visits every node of nodeType, paging internally.
// An empty nodeType visits every node.
func (s *Store) ForEachNode(ctx context.Context, nodeType string, visit func(Node) error) error {
	cursor := ""
	for {
		page, err := s.ListNodes(ctx, nodeType, MaxNodePageSize, cursor)
		if err != nil {
			return err
		}
		for _, node := range page.Nodes {
			if err := visit(node); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		if page.NextCursor == cursor {
			return fmt.Errorf("node page did not advance")
		}
		cursor = page.NextCursor
	}
}

// ForEachFinding visits every finding, paging internally.
func (s *Store) ForEachFinding(ctx context.Context, visit func(FindingView) error) error {
	cursor := ""
	for {
		page, err := s.ListFindings(ctx, MaxFindingPageSize, cursor)
		if err != nil {
			return err
		}
		for _, finding := range page.Findings {
			if err := visit(finding); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		if page.NextCursor == cursor {
			return fmt.Errorf("finding page did not advance")
		}
		cursor = page.NextCursor
	}
}

func (s *Store) ListNodes(ctx context.Context, nodeType string, limit int, cursor string) (NodePage, error) {
	limit = boundPage(limit, MaxNodePageSize)
	if nodeType != "" {
		return s.listNodesOfType(ctx, nodeType, limit, cursor)
	}
	return s.listAllNodes(ctx, limit, cursor)
}

func (s *Store) listNodesOfType(ctx context.Context, nodeType string, limit int, rawCursor string) (NodePage, error) {
	var page NodePage
	key, hasCursor, err := decodeCursor(rawCursor, cursorNodesOfType)
	if err != nil {
		return page, err
	}
	if hasCursor && key.Type != nodeType {
		return page, ErrInvalidCursor
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, type, name, provider, region, account_id, properties
		FROM nodes
		WHERE type = $1
		  AND (NOT $2::boolean OR (name, id) > ($3::text, $4::text))
		ORDER BY name, id
		LIMIT $5
	`, nodeType, hasCursor, key.Name, key.ID, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	nodes, err := scanNodes(rows)
	if err != nil {
		return page, err
	}
	page.Nodes = nodesOrEmpty(nodes)
	if len(page.Nodes) <= limit {
		return page, nil
	}
	page.Nodes = page.Nodes[:limit]
	last := page.Nodes[len(page.Nodes)-1]
	page.NextCursor, err = encodeCursor(pageCursor{
		Kind: cursorNodesOfType,
		Type: nodeType,
		Name: last.Name,
		ID:   last.ID,
	})
	return page, err
}

func (s *Store) listAllNodes(ctx context.Context, limit int, rawCursor string) (NodePage, error) {
	var page NodePage
	key, hasCursor, err := decodeCursor(rawCursor, cursorAllNodes)
	if err != nil {
		return page, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, type, name, provider, region, account_id, properties
		FROM nodes
		WHERE (NOT $1::boolean OR (type, name, id) > ($2::text, $3::text, $4::text))
		ORDER BY type, name, id
		LIMIT $5
	`, hasCursor, key.Type, key.Name, key.ID, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	nodes, err := scanNodes(rows)
	if err != nil {
		return page, err
	}
	page.Nodes = nodesOrEmpty(nodes)
	if len(page.Nodes) <= limit {
		return page, nil
	}
	page.Nodes = page.Nodes[:limit]
	last := page.Nodes[len(page.Nodes)-1]
	page.NextCursor, err = encodeCursor(pageCursor{
		Kind: cursorAllNodes,
		Type: last.Type,
		Name: last.Name,
		ID:   last.ID,
	})
	return page, err
}

func (s *Store) ListEdges(ctx context.Context, limit int, cursor string) (EdgePage, error) {
	var page EdgePage
	limit = boundPage(limit, MaxEdgePageSize)
	key, hasCursor, err := decodeCursor(cursor, cursorEdges)
	if err != nil {
		return page, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, source_id, target_id, type, properties
		FROM edges
		WHERE (NOT $1::boolean OR (type, source_id, id) > ($2::text, $3::text, $4::text))
		ORDER BY type, source_id, id
		LIMIT $5
	`, hasCursor, key.Type, key.SourceID, key.ID, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	var edges []Edge
	for rows.Next() {
		edge, err := scanEdge(rows)
		if err != nil {
			return page, err
		}
		edges = append(edges, edge)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	page.Edges = edgesOrEmpty(edges)
	if len(page.Edges) <= limit {
		return page, nil
	}
	page.Edges = page.Edges[:limit]
	last := page.Edges[len(page.Edges)-1]
	page.NextCursor, err = encodeCursor(pageCursor{
		Kind:     cursorEdges,
		Type:     last.Type,
		SourceID: last.SourceID,
		ID:       last.ID,
	})
	return page, err
}

func (s *Store) ListFindings(ctx context.Context, limit int, cursor string) (FindingPage, error) {
	var page FindingPage
	limit = boundPage(limit, MaxFindingPageSize)
	key, hasCursor, err := decodeCursor(cursor, cursorFindings)
	if err != nil {
		return page, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			f.id, f.type, f.name, f.provider, f.region, f.account_id, f.properties,
			t.id, t.name, t.type,
			COALESCE((f.properties->>'normalized_score')::double precision, -1)
		FROM nodes f
		LEFT JOIN edges e ON e.source_id = f.id AND e.type = $1
		LEFT JOIN nodes t ON t.id = e.target_id
		WHERE f.type = $2
		  AND (
		    NOT $3::boolean
		    OR COALESCE((f.properties->>'normalized_score')::double precision, -1) < $4::double precision
		    OR (
		      COALESCE((f.properties->>'normalized_score')::double precision, -1) = $4::double precision
		      AND (f.name, f.id) > ($5::text, $6::text)
		    )
		  )
		ORDER BY COALESCE((f.properties->>'normalized_score')::double precision, -1) DESC, f.name, f.id
		LIMIT $7
	`, EdgeViolates, NodeFinding, hasCursor, key.Score, key.Name, key.ID, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	var findings []FindingView
	var scores []float64
	for rows.Next() {
		var view FindingView
		var fPropsRaw []byte
		var targetID, targetName, targetType *string
		var score float64
		if err := rows.Scan(
			&view.Finding.ID, &view.Finding.Type, &view.Finding.Name,
			&view.Finding.Provider, &view.Finding.Region, &view.Finding.AccountID,
			&fPropsRaw, &targetID, &targetName, &targetType, &score,
		); err != nil {
			return page, err
		}
		view.Finding.Properties = map[string]any{}
		if len(fPropsRaw) > 0 {
			_ = decodeJSON(fPropsRaw, &view.Finding.Properties)
		}
		if targetID != nil {
			view.AffectedResourceID = *targetID
		}
		if targetName != nil {
			view.AffectedResourceName = *targetName
		}
		if targetType != nil {
			view.AffectedResourceType = *targetType
		}
		view.Path = pathIDs(view.Finding.Properties)
		findings = append(findings, view)
		scores = append(scores, score)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	page.Findings = findingsOrEmpty(findings)
	if len(page.Findings) <= limit {
		return page, nil
	}
	page.Findings = page.Findings[:limit]
	last := page.Findings[len(page.Findings)-1]
	page.NextCursor, err = encodeCursor(pageCursor{
		Kind:  cursorFindings,
		Name:  last.Finding.Name,
		ID:    last.Finding.ID,
		Score: scores[limit-1],
	})
	return page, err
}

func boundPage(limit, max int) int {
	if limit <= 0 || limit > max {
		return max
	}
	return limit
}

func decodeCursor(raw, kind string) (pageCursor, bool, error) {
	if raw == "" {
		return pageCursor{}, false, nil
	}
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return pageCursor{}, false, ErrInvalidCursor
	}
	var cursor pageCursor
	if err := json.Unmarshal(buf, &cursor); err != nil || cursor.Kind != kind || cursor.ID == "" {
		return pageCursor{}, false, ErrInvalidCursor
	}
	return cursor, true, nil
}

func encodeCursor(cursor pageCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func nodesOrEmpty(nodes []Node) []Node {
	if nodes == nil {
		return []Node{}
	}
	return nodes
}

func edgesOrEmpty(edges []Edge) []Edge {
	if edges == nil {
		return []Edge{}
	}
	return edges
}

func findingsOrEmpty(findings []FindingView) []FindingView {
	if findings == nil {
		return []FindingView{}
	}
	return findings
}
