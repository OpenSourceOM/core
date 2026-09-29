// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
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

// Ping reports whether the database connection pool can reach PostgreSQL.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) UpsertBatch(ctx context.Context, batch Batch) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := upsertBatch(ctx, tx, batch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Scope is the inventory a scan replaces.
//
// An empty Regions list covers every region of AccountID. Pass the scanned
// region and "" to replace one AWS region plus account-global IAM and S3
// (those nodes are stored with an empty region) without deleting other regions.
// Namespace, when set, limits replacement to Kubernetes nodes in that namespace.
type Scope struct {
	AccountID string
	Regions   []string
	Namespace string
}

// ReplaceInventory upserts batch, then deletes inventory in scopes that the
// batch no longer contains. Finding nodes stay unless their affected resource
// was removed. Rule evaluation removes CSPM findings that no longer match.
func (s *Store) ReplaceInventory(ctx context.Context, scopes []Scope, batch Batch) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := upsertBatch(ctx, tx, batch); err != nil {
		return err
	}
	if err := deleteAbsentInventory(ctx, tx, scopes, batch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func upsertBatch(ctx context.Context, tx pgx.Tx, batch Batch) error {
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
	return nil
}

// scopeMatch is true when node n belongs to a scan scope row s.
const scopeMatch = `
s.account_id = n.account_id
AND (s.all_regions OR n.region = s.region)
AND (COALESCE(s.namespace, '') = '' OR COALESCE(n.properties->>'namespace', '') = s.namespace)`

const scopeRows = `
jsonb_to_recordset($1::jsonb) AS s(
	account_id text,
	region text,
	all_regions boolean,
	namespace text
)`

type scopeRecord struct {
	AccountID  string `json:"account_id"`
	Region     string `json:"region"`
	AllRegions bool   `json:"all_regions"`
	Namespace  string `json:"namespace"`
}

func scopeRecords(scopes []Scope) []scopeRecord {
	var records []scopeRecord
	for _, scope := range scopes {
		if scope.AccountID == "" {
			continue
		}
		if len(scope.Regions) == 0 {
			records = append(records, scopeRecord{
				AccountID:  scope.AccountID,
				AllRegions: true,
				Namespace:  scope.Namespace,
			})
			continue
		}
		seen := map[string]bool{}
		for _, region := range scope.Regions {
			if seen[region] {
				continue
			}
			seen[region] = true
			records = append(records, scopeRecord{
				AccountID:  scope.AccountID,
				Region:     region,
				AllRegions: false,
				Namespace:  scope.Namespace,
			})
		}
	}
	return records
}

func deleteAbsentInventory(ctx context.Context, tx pgx.Tx, scopes []Scope, batch Batch) error {
	records := scopeRecords(scopes)
	if len(records) == 0 {
		return nil
	}
	scopeJSON, err := json.Marshal(records)
	if err != nil {
		return err
	}

	keepNodes := make([]string, len(batch.Nodes))
	for i, node := range batch.Nodes {
		keepNodes[i] = node.ID
	}
	sources := make([]string, len(batch.Edges))
	targets := make([]string, len(batch.Edges))
	edgeTypes := make([]string, len(batch.Edges))
	for i, edge := range batch.Edges {
		sources[i] = edge.SourceID
		targets[i] = edge.TargetID
		edgeTypes[i] = edge.Type
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM nodes n
		WHERE n.type <> $2
		  AND NOT (n.id = ANY($3::text[]))
		  AND EXISTS (
		    SELECT 1 FROM `+scopeRows+`
		    WHERE `+scopeMatch+`
		  )
	`, string(scopeJSON), NodeFinding, keepNodes); err != nil {
		return fmt.Errorf("delete absent inventory: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM edges e
		WHERE e.type <> $2
		  AND NOT EXISTS (
		    SELECT 1
		    FROM unnest($3::text[], $4::text[], $5::text[]) AS b(source_id, target_id, edge_type)
		    WHERE b.source_id = e.source_id
		      AND b.target_id = e.target_id
		      AND b.edge_type = e.type
		  )
		  AND EXISTS (
		    SELECT 1 FROM nodes n
		    WHERE n.id IN (e.source_id, e.target_id)
		      AND n.type <> $6
		      AND n.account_id <> ''
		      AND EXISTS (
		        SELECT 1 FROM `+scopeRows+`
		        WHERE `+scopeMatch+`
		      )
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM nodes n
		    WHERE n.id IN (e.source_id, e.target_id)
		      AND n.type <> $6
		      AND n.account_id <> ''
		      AND NOT EXISTS (
		        SELECT 1 FROM `+scopeRows+`
		        WHERE `+scopeMatch+`
		      )
		  )
	`, string(scopeJSON), EdgeViolates, sources, targets, edgeTypes, NodeFinding); err != nil {
		return fmt.Errorf("delete absent edges: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM nodes f
		WHERE f.type = $2
		  AND f.account_id IN (
		    SELECT s.account_id
		    FROM jsonb_to_recordset($1::jsonb) AS s(account_id text)
		  )
		  AND COALESCE(f.properties->>'affected_resource', '') <> ''
		  AND NOT EXISTS (
		    SELECT 1 FROM nodes t
		    WHERE t.id = f.properties->>'affected_resource'
		  )
	`, string(scopeJSON), NodeFinding); err != nil {
		return fmt.Errorf("delete orphan findings: %w", err)
	}
	return nil
}

// DeleteStaleRuleFindings removes CSPM findings for ruleID whose ids are not in
// keepIDs. Findings from other rules and from CVE enrichment are left alone.
func (s *Store) DeleteStaleRuleFindings(ctx context.Context, ruleID string, keepIDs []string) error {
	if ruleID == "" {
		return nil
	}
	if keepIDs == nil {
		keepIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		DELETE FROM nodes
		WHERE type = $1
		  AND properties->>'finding_type' = 'cspm'
		  AND properties->>'rule_id' = $2
		  AND NOT (id = ANY($3::text[]))
	`, NodeFinding, ruleID, keepIDs)
	return err
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

// DeleteByAccount removes every node for the given accounts, including findings.
// Scans use ReplaceInventory so a rescan can drop inventory without wiping
// findings that still apply.
func (s *Store) DeleteByAccount(ctx context.Context, accountIDs []string) error {
	if len(accountIDs) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM nodes WHERE account_id = ANY($1)`, accountIDs)
	return err
}

// ReachableFromInternet reports whether nodeID can be reached from the internet
// by following REACHABLE edges only. Identity and data hops use other edge types.
func (s *Store) ReachableFromInternet(ctx context.Context, nodeID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		WITH RECURSIVE reach AS (
			SELECT e.target_id AS node_id, 1 AS depth, ARRAY[e.source_id, e.target_id] AS seen
			FROM edges e
			WHERE e.source_id = $1 AND e.type = $2

			UNION ALL

			SELECT e.target_id, r.depth + 1, r.seen || e.target_id
			FROM edges e
			INNER JOIN reach r ON e.source_id = r.node_id
			WHERE e.type = $2
			  AND r.depth < 8
			  AND NOT e.target_id = ANY (r.seen)
		)
		SELECT EXISTS (SELECT 1 FROM reach WHERE node_id = $3)
	`, InternetNodeID, EdgeReachable, nodeID).Scan(&exists)
	return exists, err
}

func (s *Store) InternetReachableWorkloadIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE reach AS (
			SELECT e.target_id AS node_id, 1 AS depth, ARRAY[e.source_id, e.target_id] AS seen
			FROM edges e
			WHERE e.source_id = $1 AND e.type = $2

			UNION ALL

			SELECT e.target_id, r.depth + 1, r.seen || e.target_id
			FROM edges e
			INNER JOIN reach r ON e.source_id = r.node_id
			WHERE e.type = $2
			  AND r.depth < 8
			  AND NOT e.target_id = ANY (r.seen)
		)
		SELECT DISTINCT n.id
		FROM reach r
		INNER JOIN nodes n ON n.id = r.node_id
		WHERE n.type = $3
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
