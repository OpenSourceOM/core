// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "context"

// FindingTypeAttackPath is the finding_type of a row that records an
// internet-to-datastore path. Those rows are not themselves sources for
// another attack-path finding.
const FindingTypeAttackPath = "attack_path"

// AttackPathCombination is one existing finding on an internet-reachable
// workload, paired with a datastore that workload can reach.
type AttackPathCombination struct {
	Workload  Node
	Datastore Node
	Finding   Node
	Path      []string
}

// ListAttackPathCombinations returns one row per finding on an
// internet-reachable workload and a datastore that workload can reach.
//
// Reach is a CAN_ACCESS edge from the workload, or ASSUMES to an identity
// that has CAN_ACCESS. Path is the shortest REACHABLE walk from the internet
// to the workload, then that access hop. When both hops reach the same
// datastore, the shorter path is kept. Findings whose finding_type is
// attack_path are not sources. Sensitivity is not a filter.
func (s *Store) ListAttackPathCombinations(ctx context.Context) ([]AttackPathCombination, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE reach AS (
			SELECT
				e.target_id AS node_id,
				ARRAY[e.source_id, e.target_id] AS node_ids,
				1 AS depth
			FROM edges e
			WHERE e.source_id = $1 AND e.type = $2

			UNION ALL

			SELECT
				e.target_id,
				r.node_ids || e.target_id,
				r.depth + 1
			FROM edges e
			INNER JOIN reach r ON e.source_id = r.node_id
			WHERE e.type = $2
			  AND r.depth < $3
			  AND NOT e.target_id = ANY (r.node_ids)
		),
		workload_path AS (
			SELECT DISTINCT ON (r.node_id)
				r.node_id,
				r.node_ids
			FROM reach r
			INNER JOIN nodes w ON w.id = r.node_id AND w.type = $4
			ORDER BY r.node_id, r.depth
		),
		hops AS (
			SELECT
				wp.node_id AS workload_id,
				d.id AS datastore_id,
				f.id AS finding_id,
				wp.node_ids || d.id AS path
			FROM workload_path wp
			INNER JOIN edges v ON v.target_id = wp.node_id AND v.type = $5
			INNER JOIN nodes f ON f.id = v.source_id AND f.type = $6
				AND COALESCE(f.properties->>'finding_type', '') <> $11
			INNER JOIN edges a ON a.source_id = wp.node_id AND a.type = $7
			INNER JOIN nodes d ON d.id = a.target_id AND d.type = $8
			WHERE NOT (d.id = ANY (wp.node_ids))

			UNION ALL

			SELECT
				wp.node_id,
				d.id,
				f.id,
				wp.node_ids || i.id || d.id
			FROM workload_path wp
			INNER JOIN edges v ON v.target_id = wp.node_id AND v.type = $5
			INNER JOIN nodes f ON f.id = v.source_id AND f.type = $6
				AND COALESCE(f.properties->>'finding_type', '') <> $11
			INNER JOIN edges assumes ON assumes.source_id = wp.node_id AND assumes.type = $9
			INNER JOIN nodes i ON i.id = assumes.target_id AND i.type = $10
			INNER JOIN edges a ON a.source_id = i.id AND a.type = $7
			INNER JOIN nodes d ON d.id = a.target_id AND d.type = $8
			WHERE NOT (i.id = ANY (wp.node_ids))
			  AND NOT (d.id = ANY (wp.node_ids || i.id))
		)
		SELECT DISTINCT ON (finding_id, datastore_id)
			workload_id, datastore_id, finding_id, path
		FROM hops
		ORDER BY finding_id, datastore_id, cardinality(path), path
	`, InternetNodeID, EdgeReachable, internetDatastoreDepth, NodeWorkload,
		EdgeViolates, NodeFinding, EdgeCanAccess, NodeDatastore, EdgeAssumes, NodeIdentity,
		FindingTypeAttackPath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var combos []AttackPathCombination
	for rows.Next() {
		var workloadID, datastoreID, findingID string
		var path []string
		if err := rows.Scan(&workloadID, &datastoreID, &findingID, &path); err != nil {
			return nil, err
		}
		workload, err := s.GetNode(ctx, workloadID)
		if err != nil {
			return nil, err
		}
		datastore, err := s.GetNode(ctx, datastoreID)
		if err != nil {
			return nil, err
		}
		finding, err := s.GetNode(ctx, findingID)
		if err != nil {
			return nil, err
		}
		combos = append(combos, AttackPathCombination{
			Workload:  workload,
			Datastore: datastore,
			Finding:   finding,
			Path:      path,
		})
	}
	return combos, rows.Err()
}

func pathIDs(props map[string]any) []string {
	raw, ok := props["path"]
	if !ok || raw == nil {
		return nil
	}
	switch ids := raw.(type) {
	case []string:
		if len(ids) == 0 {
			return nil
		}
		return ids
	case []any:
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			s, ok := id.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}
