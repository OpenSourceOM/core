// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) UpsertBatch(ctx context.Context, batch Batch) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, node := range batch.Nodes {
		props, err := node.PropertiesJSON()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO nodes (id, type, name, provider, region, account_id, properties, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (id) DO UPDATE SET
				type = EXCLUDED.type,
				name = EXCLUDED.name,
				provider = EXCLUDED.provider,
				region = EXCLUDED.region,
				account_id = EXCLUDED.account_id,
				properties = EXCLUDED.properties,
				updated_at = now()
		`, node.ID, node.Type, node.Name, node.Provider, node.Region, node.AccountID, props)
		if err != nil {
			return fmt.Errorf("upsert node %s: %w", node.ID, err)
		}
	}

	for _, edge := range batch.Edges {
		props, err := edge.PropertiesJSON()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO edges (id, source_id, target_id, type, properties)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (source_id, target_id, type) DO UPDATE SET
				id = EXCLUDED.id,
				properties = EXCLUDED.properties
		`, edge.ID, edge.SourceID, edge.TargetID, edge.Type, props)
		if err != nil {
			return fmt.Errorf("upsert edge %s: %w", edge.ID, err)
		}
	}

	return tx.Commit(ctx)
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	stats.ByType = map[string]int{}

	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&stats.Nodes); err != nil {
		return stats, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM edges`).Scan(&stats.Edges); err != nil {
		return stats, err
	}

	rows, err := s.pool.Query(ctx, `SELECT type, COUNT(*) FROM nodes GROUP BY type ORDER BY type`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var nodeType string
		var count int
		if err := rows.Scan(&nodeType, &count); err != nil {
			return stats, err
		}
		stats.ByType[nodeType] = count
	}
	return stats, rows.Err()
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

func (s *Store) ListNodes(ctx context.Context, nodeType string, limit int) ([]Node, error) {
	if limit <= 0 {
		limit = 500
	}
	query := `
		SELECT id, type, name, provider, region, account_id, properties
		FROM nodes
	`
	args := []any{limit}
	if nodeType != "" {
		query += ` WHERE type = $1 ORDER BY name LIMIT $2`
		args = []any{nodeType, limit}
	} else {
		query += ` ORDER BY type, name LIMIT $1`
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (s *Store) ListEdges(ctx context.Context, limit int) ([]Edge, error) {
	if limit <= 0 {
		limit = 2000
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, source_id, target_id, type, properties
		FROM edges
		ORDER BY type, source_id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []Edge
	for rows.Next() {
		edge, err := scanEdge(rows)
		if err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context, limit int) ([]FindingView, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			f.id, f.type, f.name, f.provider, f.region, f.account_id, f.properties,
			t.id, t.name, t.type
		FROM nodes f
		LEFT JOIN edges e ON e.source_id = f.id AND e.type = $1
		LEFT JOIN nodes t ON t.id = e.target_id
		WHERE f.type = $2
		ORDER BY (f.properties->>'normalized_score')::float DESC NULLS LAST, f.name
		LIMIT $3
	`, EdgeViolates, NodeFinding, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []FindingView
	for rows.Next() {
		var view FindingView
		var fPropsRaw []byte
		var targetID, targetName, targetType *string
		if err := rows.Scan(
			&view.Finding.ID, &view.Finding.Type, &view.Finding.Name,
			&view.Finding.Provider, &view.Finding.Region, &view.Finding.AccountID,
			&fPropsRaw, &targetID, &targetName, &targetType,
		); err != nil {
			return nil, err
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
		findings = append(findings, view)
	}
	return findings, rows.Err()
}

func (s *Store) InternetReachableWorkloadIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT e.target_id
		FROM edges e
		INNER JOIN nodes n ON n.id = e.target_id
		WHERE e.source_id = $1
		  AND e.type = $2
		  AND n.type = $3
	`, InternetNodeID, EdgeReachable, NodeWorkload)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id string) (Node, error) {
	var node Node
	var props []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, type, name, provider, region, account_id, properties
		FROM nodes WHERE id = $1
	`, id).Scan(&node.ID, &node.Type, &node.Name, &node.Provider, &node.Region, &node.AccountID, &props)
	if err != nil {
		return node, err
	}
	node.Properties = map[string]any{}
	if len(props) > 0 {
		_ = decodeJSON(props, &node.Properties)
	}
	return node, nil
}

func decodeJSON(data []byte, target *map[string]any) error {
	return json.Unmarshal(data, target)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (Node, error) {
	var node Node
	var props []byte
	if err := row.Scan(&node.ID, &node.Type, &node.Name, &node.Provider, &node.Region, &node.AccountID, &props); err != nil {
		return node, err
	}
	node.Properties = map[string]any{}
	if len(props) > 0 {
		_ = decodeJSON(props, &node.Properties)
	}
	return node, nil
}

func scanNodes(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Node, error) {
	var nodes []Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func scanEdge(row rowScanner) (Edge, error) {
	var edge Edge
	var props []byte
	if err := row.Scan(&edge.ID, &edge.SourceID, &edge.TargetID, &edge.Type, &props); err != nil {
		return edge, err
	}
	edge.Properties = map[string]any{}
	if len(props) > 0 {
		_ = decodeJSON(props, &edge.Properties)
	}
	return edge, nil
}
