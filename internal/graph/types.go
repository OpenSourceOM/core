// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"encoding/json"

	"github.com/OpenSourceOM/core/sdk/collector"
)

// Node and edge type strings match the public collector SDK (schema v0).
const (
	NodeInternet  = collector.NodeInternet
	NodeNetwork   = collector.NodeNetwork
	NodeWorkload  = collector.NodeWorkload
	NodeIdentity  = collector.NodeIdentity
	NodeDatastore = collector.NodeDatastore
	NodeFinding   = collector.NodeFinding
	NodeControl   = collector.NodeControl
)

const (
	EdgeReachable = collector.EdgeReachable
	EdgeAssumes   = collector.EdgeAssumes
	EdgeCanAccess = collector.EdgeCanAccess
	EdgeAffects   = collector.EdgeAffects
	EdgeViolates  = collector.EdgeViolates
)

// InternetNodeID is the stable id of the synthetic internet node.
const InternetNodeID = collector.InternetNodeID

type Node struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Provider   string         `json:"provider,omitempty"`
	Region     string         `json:"region,omitempty"`
	AccountID  string         `json:"account_id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Edge struct {
	ID         string         `json:"id"`
	SourceID   string         `json:"source_id"`
	TargetID   string         `json:"target_id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Batch struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Stats struct {
	Nodes  int            `json:"nodes"`
	Edges  int            `json:"edges"`
	ByType map[string]int `json:"by_type"`
}

type PathResult struct {
	Query   string   `json:"query"`
	Paths   [][]Node `json:"paths"`
	Summary string   `json:"summary"`
	// Truncated is true when a path cap or depth cap dropped rows.
	Truncated bool `json:"truncated"`
	// Truncation names the cap that cut the result: "path cap", "depth cap",
	// or "path cap and depth cap". Empty when Truncated is false.
	Truncation string `json:"truncation,omitempty"`
}

type FindingView struct {
	Finding              Node   `json:"finding"`
	AffectedResourceID   string `json:"affected_resource_id,omitempty"`
	AffectedResourceName string `json:"affected_resource_name,omitempty"`
	AffectedResourceType string `json:"affected_resource_type,omitempty"`
	// Path is the ordered node ids recorded on an attack-path finding.
	Path []string `json:"path,omitempty"`
}

type GraphSnapshot struct {
	Nodes           []Node `json:"nodes"`
	Edges           []Edge `json:"edges"`
	NextNodesCursor string `json:"next_nodes_cursor,omitempty"`
	NextEdgesCursor string `json:"next_edges_cursor,omitempty"`
}

// Page sizes are ceilings. A caller cannot raise them to read the whole table
// in one response. Follow NextCursor to read the rest.
const (
	MaxNodePageSize    = 500
	MaxEdgePageSize    = 2000
	MaxFindingPageSize = 200
)

type NodePage struct {
	Nodes      []Node `json:"nodes"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type EdgePage struct {
	Edges      []Edge `json:"edges"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type FindingPage struct {
	Findings   []FindingView `json:"findings"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func (n Node) PropertiesJSON() ([]byte, error) {
	if n.Properties == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(n.Properties)
}

func (e Edge) PropertiesJSON() ([]byte, error) {
	if e.Properties == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(e.Properties)
}
