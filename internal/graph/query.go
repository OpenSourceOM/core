// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const InternetNodeID = "internet:global"

var NamedQueries = map[string]string{
	"internet-to-workload":            "Paths from the internet to reachable workloads",
	"internet-to-datastore":         "Paths from the internet through workloads to datastores",
	"public-s3-buckets":             "S3 buckets with public exposure indicators",
	"admin-identities":              "IAM roles with broad administrative permissions",
	"toxic-s3-public-with-admin-role": "Public S3 buckets linked to admin-capable identities",
}

type Querier struct {
	store *Store
}

func NewQuerier(store *Store) *Querier {
	return &Querier{store: store}
}

func (q *Querier) Run(ctx context.Context, name string) (PathResult, error) {
	switch name {
	case "internet-to-workload":
		return q.internetToWorkload(ctx)
	case "internet-to-datastore":
		return q.internetToDatastore(ctx)
	case "public-s3-buckets":
		return q.publicS3Buckets(ctx)
	case "admin-identities":
		return q.adminIdentities(ctx)
	case "toxic-s3-public-with-admin-role":
		return q.toxicS3PublicWithAdmin(ctx)
	default:
		return PathResult{}, fmt.Errorf("unknown query %q", name)
	}
}

func (q *Querier) internetToWorkload(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		WITH RECURSIVE paths AS (
			SELECT
				e.source_id,
				e.target_id,
				ARRAY[e.source_id, e.target_id] AS node_ids,
				1 AS depth
			FROM edges e
			WHERE e.source_id = $1

			UNION ALL

			SELECT
				e.source_id,
				e.target_id,
				p.node_ids || e.target_id,
				p.depth + 1
			FROM edges e
			INNER JOIN paths p ON e.source_id = p.target_id
			WHERE p.depth < 6
			  AND NOT e.target_id = ANY (p.node_ids)
		)
		SELECT DISTINCT node_ids
		FROM paths p
		INNER JOIN nodes n ON n.id = p.target_id
		WHERE n.type = $2
		LIMIT 50
	`, InternetNodeID, NodeWorkload)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	return q.materializePaths(ctx, rows, "internet-to-workload",
		"Attack paths from the internet to reachable workloads")
}

func (q *Querier) internetToDatastore(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		WITH RECURSIVE paths AS (
			SELECT
				e.source_id,
				e.target_id,
				ARRAY[e.source_id, e.target_id] AS node_ids,
				1 AS depth
			FROM edges e
			WHERE e.source_id = $1

			UNION ALL

			SELECT
				e.source_id,
				e.target_id,
				p.node_ids || e.target_id,
				p.depth + 1
			FROM edges e
			INNER JOIN paths p ON e.source_id = p.target_id
			WHERE p.depth < 8
			  AND NOT e.target_id = ANY (p.node_ids)
		)
		SELECT DISTINCT node_ids
		FROM paths p
		INNER JOIN nodes n ON n.id = p.target_id
		WHERE n.type = $2
		  AND EXISTS (
			SELECT 1
			FROM unnest(p.node_ids) AS nid
			INNER JOIN nodes w ON w.id = nid AND w.type = $3
		  )
		LIMIT 50
	`, InternetNodeID, NodeDatastore, NodeWorkload)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	return q.materializePaths(ctx, rows, "internet-to-datastore",
		"Attack paths from the internet through workloads to datastores")
}

func (q *Querier) publicS3Buckets(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		SELECT ARRAY[n.id]
		FROM nodes n
		WHERE n.type = $1
		  AND (
			(n.properties->>'public_access')::boolean IS TRUE
		 OR n.properties->>'public_access_block' = 'disabled'
		  )
		ORDER BY n.name
		LIMIT 100
	`, NodeDatastore)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	return q.materializeSingleNodePaths(ctx, rows, "public-s3-buckets",
		"S3 buckets flagged as publicly accessible or missing public access blocks")
}

func (q *Querier) adminIdentities(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		SELECT ARRAY[n.id]
		FROM nodes n
		WHERE n.type = $1
		  AND (
			n.properties->>'admin_access' = 'true'
		 OR n.name LIKE '*Admin%'
		 OR n.name LIKE '*admin*'
		  )
		ORDER BY n.name
		LIMIT 100
	`, NodeIdentity)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	return q.materializeSingleNodePaths(ctx, rows, "admin-identities",
		"IAM roles with indicators of broad administrative access")
}

func (q *Querier) toxicS3PublicWithAdmin(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		SELECT ARRAY[s.id, i.id]
		FROM nodes s
		INNER JOIN edges e ON e.target_id = s.id AND e.type = $1
		INNER JOIN nodes i ON i.id = e.source_id AND i.type = $2
		WHERE s.type = $3
		  AND (
			(s.properties->>'public_access')::boolean IS TRUE
		 OR s.properties->>'public_access_block' = 'disabled'
		  )
		  AND i.properties->>'admin_access' = 'true'
		LIMIT 50
	`, EdgeCanAccess, NodeIdentity, NodeDatastore)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}

	return PathResult{
		Query:   "toxic-s3-public-with-admin-role",
		Paths:   paths,
		Summary: "Public S3 buckets reachable by identities with admin-level permissions",
	}, nil
}

func (q *Querier) materializePaths(ctx context.Context, rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}, queryName, summary string) (PathResult, error) {
	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	return PathResult{Query: queryName, Paths: paths, Summary: summary}, nil
}

func (q *Querier) materializeSingleNodePaths(ctx context.Context, rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}, queryName, summary string) (PathResult, error) {
	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	return PathResult{Query: queryName, Paths: paths, Summary: summary}, nil
}

func (q *Querier) readPathRows(ctx context.Context, rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([][]Node, error) {
	var paths [][]Node
	for rows.Next() {
		var ids []string
		if err := rows.Scan(&ids); err != nil {
			return nil, err
		}
		path, err := q.loadNodes(ctx, ids)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}

func (q *Querier) loadNodes(ctx context.Context, ids []string) ([]Node, error) {
	var path []Node
	for _, id := range ids {
		node, err := q.store.GetNode(ctx, id)
		if err != nil {
			return nil, err
		}
		path = append(path, node)
	}
	return path, nil
}

func FormatPath(path []Node) string {
	names := make([]string, len(path))
	for i, n := range path {
		names[i] = fmt.Sprintf("%s(%s)", n.Name, n.Type)
	}
	return strings.Join(names, " → ")
}

func MustProperties(props map[string]any) map[string]any {
	if props == nil {
		return map[string]any{}
	}
	return props
}

func PropertiesFromJSON(data []byte) map[string]any {
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return out
}
