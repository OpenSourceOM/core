// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

var NamedQueries = map[string]string{
	"internet-to-workload":            "Paths from the internet to reachable workloads",
	"internet-to-datastore":           "Paths from the internet through workloads to datastores",
	"internet-to-sensitive-datastore": "Paths from the internet through workloads to datastores marked with sensitivity",
	"public-datastore":                "Datastores with public exposure indicators",
	"admin-identities":                "Identities with broad administrative permissions",
	"admin-to-public-datastore":       "Public datastores linked to admin-capable identities",
}

// queryAliases keeps the Phase 0 S3 names working. They are not listed.
var queryAliases = map[string]string{
	"public-s3-buckets":               "public-datastore",
	"toxic-s3-public-with-admin-role": "admin-to-public-datastore",
}

type Querier struct {
	store *Store
}

func NewQuerier(store *Store) *Querier {
	return &Querier{store: store}
}

func (q *Querier) Run(ctx context.Context, name string) (PathResult, error) {
	switch resolveQuery(name) {
	case "internet-to-workload":
		return q.internetToWorkload(ctx)
	case "internet-to-datastore":
		return q.internetToDatastore(ctx, false)
	case "internet-to-sensitive-datastore":
		return q.internetToDatastore(ctx, true)
	case "public-datastore":
		return q.publicDatastores(ctx, name)
	case "admin-identities":
		return q.adminIdentities(ctx)
	case "admin-to-public-datastore":
		return q.adminToPublicDatastore(ctx, name)
	default:
		return PathResult{}, fmt.Errorf("unknown query %q", name)
	}
}

func resolveQuery(name string) string {
	if canonical, ok := queryAliases[name]; ok {
		return canonical
	}
	return name
}

const (
	internetWorkloadDepth  = 6
	internetWorkloadCap    = 50
	internetDatastoreDepth = 8
	internetDatastoreCap   = 50
	nodeListCap            = 100
	pairPathCap            = 50
)

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
			WHERE p.depth < $3
			  AND NOT e.target_id = ANY (p.node_ids)
		)
		SELECT DISTINCT node_ids
		FROM paths p
		INNER JOIN nodes n ON n.id = p.target_id
		WHERE n.type = $2
		LIMIT $4
	`, InternetNodeID, NodeWorkload, internetWorkloadDepth, internetWorkloadCap+1)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	depthCut, err := q.depthCut(ctx, internetWorkloadDepth)
	if err != nil {
		return PathResult{}, err
	}
	return finishPaths("internet-to-workload",
		"Attack paths from the internet to reachable workloads",
		paths, internetWorkloadCap, depthCut), nil
}

func (q *Querier) internetToDatastore(ctx context.Context, sensitiveOnly bool) (PathResult, error) {
	name := "internet-to-datastore"
	summary := "Attack paths from the internet through workloads to datastores"
	if sensitiveOnly {
		name = "internet-to-sensitive-datastore"
		summary = "Attack paths from the internet through workloads to datastores marked with sensitivity"
	}
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
			WHERE p.depth < $4
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
		  AND (
			$6 = FALSE
			OR btrim(COALESCE(n.properties->>'sensitivity', '')) <> ''
		  )
		LIMIT $5
	`, InternetNodeID, NodeDatastore, NodeWorkload, internetDatastoreDepth, internetDatastoreCap+1, sensitiveOnly)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	depthCut, err := q.depthCut(ctx, internetDatastoreDepth)
	if err != nil {
		return PathResult{}, err
	}
	return finishPaths(name, summary, paths, internetDatastoreCap, depthCut), nil
}

func (q *Querier) publicDatastores(ctx context.Context, queryName string) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		SELECT ARRAY[n.id]
		FROM nodes n
		WHERE n.type = $1
		  AND (
			(n.properties->>'public_access')::boolean IS TRUE
		 OR n.properties->>'public_access_block' = 'disabled'
		  )
		ORDER BY n.name
		LIMIT $2
	`, NodeDatastore, nodeListCap+1)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	return finishPaths(queryName,
		"Datastores flagged as publicly accessible or missing public access blocks",
		paths, nodeListCap, false), nil
}

func (q *Querier) adminIdentities(ctx context.Context) (PathResult, error) {
	rows, err := q.store.pool.Query(ctx, `
		SELECT ARRAY[n.id]
		FROM nodes n
		WHERE n.type = $1
		  AND n.properties->>'admin_access' = 'true'
		ORDER BY n.name
		LIMIT $2
	`, NodeIdentity, nodeListCap+1)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	return finishPaths("admin-identities",
		"Identities with broad administrative access",
		paths, nodeListCap, false), nil
}

func (q *Querier) adminToPublicDatastore(ctx context.Context, queryName string) (PathResult, error) {
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
		LIMIT $4
	`, EdgeCanAccess, NodeIdentity, NodeDatastore, pairPathCap+1)
	if err != nil {
		return PathResult{}, err
	}
	defer rows.Close()

	paths, err := q.readPathRows(ctx, rows)
	if err != nil {
		return PathResult{}, err
	}
	return finishPaths(queryName,
		"Public datastores reachable by identities with admin-level permissions",
		paths, pairPathCap, false), nil
}

// depthCut reports whether the walk stopped at maxDepth while an unused
// outgoing edge remained. That edge may have led to a result the cap hid.
func (q *Querier) depthCut(ctx context.Context, maxDepth int) (bool, error) {
	var cut bool
	err := q.store.pool.QueryRow(ctx, `
		WITH RECURSIVE paths AS (
			SELECT
				e.target_id,
				ARRAY[e.source_id, e.target_id] AS node_ids,
				1 AS depth
			FROM edges e
			WHERE e.source_id = $1

			UNION ALL

			SELECT
				e.target_id,
				p.node_ids || e.target_id,
				p.depth + 1
			FROM edges e
			INNER JOIN paths p ON e.source_id = p.target_id
			WHERE p.depth < $2
			  AND NOT e.target_id = ANY (p.node_ids)
		)
		SELECT EXISTS (
			SELECT 1
			FROM paths p
			INNER JOIN edges e ON e.source_id = p.target_id
			WHERE p.depth = $2
			  AND NOT e.target_id = ANY (p.node_ids)
		)
	`, InternetNodeID, maxDepth).Scan(&cut)
	return cut, err
}

func finishPaths(queryName, summary string, paths [][]Node, cap int, depthCut bool) PathResult {
	pathCap := len(paths) > cap
	if pathCap {
		paths = paths[:cap]
	}
	truncated, note := truncation(pathCap, depthCut)
	return PathResult{
		Query:      queryName,
		Paths:      paths,
		Summary:    summary,
		Truncated:  truncated,
		Truncation: note,
		Audits:     AuditsForPaths(paths),
	}
}

func truncation(pathCap, depthCap bool) (bool, string) {
	switch {
	case pathCap && depthCap:
		return true, "path cap and depth cap"
	case pathCap:
		return true, "path cap"
	case depthCap:
		return true, "depth cap"
	default:
		return false, ""
	}
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
