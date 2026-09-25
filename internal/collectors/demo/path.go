// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package demo

import (
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
)

// AttackPathIDs is Internet → sg-web → web-1 → AdminRole → prod-db.
func AttackPathIDs() []string {
	return []string{
		graph.InternetNodeID,
		SecurityGroupWebID,
		WebInstanceID,
		AdminRoleID,
		ProdDBID,
	}
}

// Hop is one checkable step on the sample attack path.
type Hop struct {
	SourceName string
	TargetName string
	Type       string
	Reason     string
}

// AttackHops returns the sample attack path with the reason stored on each edge.
func AttackHops(batch graph.Batch) ([]Hop, error) {
	names := make(map[string]string, len(batch.Nodes))
	for _, node := range batch.Nodes {
		names[node.ID] = node.Name
	}
	edges := make(map[string]graph.Edge, len(batch.Edges))
	for _, edge := range batch.Edges {
		edges[edge.SourceID+"|"+edge.TargetID] = edge
	}

	ids := AttackPathIDs()
	hops := make([]Hop, 0, len(ids)-1)
	for i := 1; i < len(ids); i++ {
		src, dst := ids[i-1], ids[i]
		edge, ok := edges[src+"|"+dst]
		if !ok {
			return nil, fmt.Errorf("missing attack-path edge %s -> %s", src, dst)
		}
		reason, _ := edge.Properties["reason"].(string)
		if strings.TrimSpace(reason) == "" {
			return nil, fmt.Errorf("attack-path edge %s -> %s has no reason", src, dst)
		}
		hops = append(hops, Hop{
			SourceName: names[src],
			TargetName: names[dst],
			Type:       edge.Type,
			Reason:     reason,
		})
	}
	return hops, nil
}
