// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "encoding/json"

// Node types (schema v0).
const (
	NodeInternet  = "Internet"
	NodeNetwork   = "Network"
	NodeWorkload  = "Workload"
	NodeIdentity  = "Identity"
	NodeDatastore = "Datastore"
	NodeFinding   = "Finding"
	NodeControl   = "Control"
)

// Edge types (schema v0).
const (
	EdgeReachable  = "REACHABLE"
	EdgeAssumes    = "ASSUMES"
	EdgeCanAccess  = "CAN_ACCESS"
	EdgeAffects    = "AFFECTS"
	EdgeViolates   = "VIOLATES"
)

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
	Nodes int            `json:"nodes"`
	Edges int            `json:"edges"`
	ByType map[string]int `json:"by_type"`
}

type PathResult struct {
	Query   string   `json:"query"`
	Paths   [][]Node `json:"paths"`
	Summary string   `json:"summary"`
}

type FindingView struct {
	Finding              Node   `json:"finding"`
	AffectedResourceID   string `json:"affected_resource_id,omitempty"`
	AffectedResourceName string `json:"affected_resource_name,omitempty"`
	AffectedResourceType string `json:"affected_resource_type,omitempty"`
}

type GraphSnapshot struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
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
