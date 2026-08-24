// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
)

type AdminDatastorePair struct {
	Identity  Node `json:"identity"`
	Datastore Node `json:"datastore"`
}

type BlastRadiusResult struct {
	Identity   Node   `json:"identity"`
	Reachable  []Node `json:"reachable"`
	EdgeCount  int    `json:"edge_count"`
	MaxDepth   int    `json:"max_depth"`
	Summary    string `json:"summary"`
}

func (s *Store) HasIncomingEdge(ctx context.Context, sourceID, targetID, edgeType string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM edges
			WHERE source_id = $1 AND target_id = $2 AND type = $3
		)
	`, sourceID, targetID, edgeType).Scan(&exists)
	return exists, err
}

func (s *Store) OnInternetDatastorePath(ctx context.Context, nodeID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		WITH RECURSIVE paths AS (
			SELECT ARRAY[e.source_id, e.target_id] AS node_ids, 1 AS depth
			FROM edges e
			WHERE e.source_id = $1
			UNION ALL
			SELECT p.node_ids || e.target_id, p.depth + 1
			FROM edges e
			INNER JOIN paths p ON e.source_id = p.node_ids[array_length(p.node_ids, 1)]
			WHERE p.depth < 8 AND NOT e.target_id = ANY(p.node_ids)
		)
		SELECT EXISTS (
			SELECT 1 FROM paths p
			WHERE $2 = ANY(p.node_ids)
			  AND EXISTS (
				SELECT 1 FROM unnest(p.node_ids) nid
				INNER JOIN nodes w ON w.id = nid AND w.type = $3
			  )
			  AND EXISTS (
				SELECT 1 FROM unnest(p.node_ids) nid
				INNER JOIN nodes d ON d.id = nid AND d.type = $4
			  )
		)
	`, InternetNodeID, nodeID, NodeWorkload, NodeDatastore).Scan(&exists)
	return exists, err
}

func (s *Store) ListAdminDatastorePairs(ctx context.Context) ([]AdminDatastorePair, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			i.id, i.type, i.name, i.provider, i.region, i.account_id, i.properties,
			d.id, d.type, d.name, d.provider, d.region, d.account_id, d.properties
		FROM edges e
		INNER JOIN nodes i ON i.id = e.source_id AND i.type = $1
		INNER JOIN nodes d ON d.id = e.target_id AND d.type = $2
		WHERE e.type = $3
		  AND i.properties->>'admin_access' = 'true'
	`, NodeIdentity, NodeDatastore, EdgeCanAccess)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pairs []AdminDatastorePair
	for rows.Next() {
		var pair AdminDatastorePair
		var iProps, dProps []byte
		if err := rows.Scan(
			&pair.Identity.ID, &pair.Identity.Type, &pair.Identity.Name,
			&pair.Identity.Provider, &pair.Identity.Region, &pair.Identity.AccountID, &iProps,
			&pair.Datastore.ID, &pair.Datastore.Type, &pair.Datastore.Name,
			&pair.Datastore.Provider, &pair.Datastore.Region, &pair.Datastore.AccountID, &dProps,
		); err != nil {
			return nil, err
		}
		pair.Identity.Properties = map[string]any{}
		pair.Datastore.Properties = map[string]any{}
		if len(iProps) > 0 {
			_ = decodeJSON(iProps, &pair.Identity.Properties)
		}
		if len(dProps) > 0 {
			_ = decodeJSON(dProps, &pair.Datastore.Properties)
		}
		pairs = append(pairs, pair)
	}
	return pairs, rows.Err()
}

func (s *Store) FindIdentityByName(ctx context.Context, name string) (Node, error) {
	var node Node
	var props []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, type, name, provider, region, account_id, properties
		FROM nodes
		WHERE type = $1 AND name = $2
		ORDER BY updated_at DESC
		LIMIT 1
	`, NodeIdentity, name).Scan(
		&node.ID, &node.Type, &node.Name, &node.Provider, &node.Region, &node.AccountID, &props,
	)
	if err != nil {
		return node, err
	}
	node.Properties = map[string]any{}
	if len(props) > 0 {
		_ = decodeJSON(props, &node.Properties)
	}
	return node, nil
}

func (s *Store) BlastRadius(ctx context.Context, identityID string, maxDepth int) (BlastRadiusResult, error) {
	if maxDepth <= 0 {
		maxDepth = 6
	}
	identity, err := s.GetNode(ctx, identityID)
	if err != nil {
		return BlastRadiusResult{}, err
	}

	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE reach AS (
			SELECT e.target_id AS node_id, 1 AS depth
			FROM edges e
			WHERE e.source_id = $1
			  AND e.type = ANY($2)

			UNION ALL

			SELECT e.target_id, r.depth + 1
			FROM edges e
			INNER JOIN reach r ON e.source_id = r.node_id
			WHERE r.depth < $3
			  AND e.type = ANY($2)
		)
		SELECT DISTINCT n.id, n.type, n.name, n.provider, n.region, n.account_id, n.properties
		FROM reach r
		INNER JOIN nodes n ON n.id = r.node_id
		ORDER BY n.type, n.name
		LIMIT 200
	`, identityID, []string{EdgeCanAccess, EdgeAssumes}, maxDepth)
	if err != nil {
		return BlastRadiusResult{}, err
	}
	defer rows.Close()

	reachable, err := scanNodes(rows)
	if err != nil {
		return BlastRadiusResult{}, err
	}

	return BlastRadiusResult{
		Identity:  identity,
		Reachable: reachable,
		MaxDepth:  maxDepth,
		Summary:   formatBlastRadiusSummary(identity, reachable),
	}, nil
}

func formatBlastRadiusSummary(identity Node, reachable []Node) string {
	counts := map[string]int{}
	for _, node := range reachable {
		counts[node.Type]++
	}
	return fmt.Sprintf(
		"Identity %s can reach %d resources (%d workloads, %d datastores, %d networks)",
		identity.Name, len(reachable), counts[NodeWorkload], counts[NodeDatastore], counts[NodeNetwork],
	)
}
