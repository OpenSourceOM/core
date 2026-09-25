// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package collector

import "fmt"

// Normalize fills default edge ids. Call it before Validate.
func Normalize(b Batch) Batch {
	for i, edge := range b.Edges {
		if edge.ID == "" {
			b.Edges[i].ID = EdgeID(edge.SourceID, edge.TargetID, edge.Type)
		}
	}
	return b
}

// Validate checks a batch against graph schema v0.
// Every edge endpoint must be a node in the same batch.
func Validate(b Batch) error {
	nodes := make(map[string]struct{}, len(b.Nodes))
	for i, node := range b.Nodes {
		if node.ID == "" {
			return fmt.Errorf("nodes[%d]: id is required", i)
		}
		if _, ok := nodes[node.ID]; ok {
			return fmt.Errorf("nodes[%d]: duplicate id %q", i, node.ID)
		}
		nodes[node.ID] = struct{}{}
		if node.Name == "" {
			return fmt.Errorf("node %q: name is required", node.ID)
		}
		if !knownNodeType(node.Type) {
			return fmt.Errorf("node %q: unknown type %q", node.ID, node.Type)
		}
	}

	edges := make(map[string]struct{}, len(b.Edges))
	for i, edge := range b.Edges {
		if edge.ID == "" {
			return fmt.Errorf("edges[%d]: id is required (call Normalize first)", i)
		}
		if _, ok := edges[edge.ID]; ok {
			return fmt.Errorf("edges[%d]: duplicate id %q", i, edge.ID)
		}
		edges[edge.ID] = struct{}{}
		if !knownEdgeType(edge.Type) {
			return fmt.Errorf("edge %q: unknown type %q", edge.ID, edge.Type)
		}
		if _, ok := nodes[edge.SourceID]; !ok {
			return fmt.Errorf("edge %q: source %q is not in the batch", edge.ID, edge.SourceID)
		}
		if _, ok := nodes[edge.TargetID]; !ok {
			return fmt.Errorf("edge %q: target %q is not in the batch", edge.ID, edge.TargetID)
		}
	}
	return nil
}

func knownNodeType(typ string) bool {
	switch typ {
	case NodeInternet, NodeNetwork, NodeWorkload, NodeIdentity, NodeDatastore, NodeFinding, NodeControl:
		return true
	default:
		return false
	}
}

func knownEdgeType(typ string) bool {
	switch typ {
	case EdgeReachable, EdgeAssumes, EdgeCanAccess, EdgeAffects, EdgeViolates:
		return true
	default:
		return false
	}
}
