// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

// Package collector is the public SDK for OpenSourceOM collector plugins.
//
// A plugin is any executable. It inherits the environment of `om`, writes a
// single graph batch JSON object to stdout, and sends diagnostics to stderr.
// `om scan plugin` validates that batch and replaces inventory for each account it contains.
//
// Go plugins can implement [Collector] and call [Run] from main. Other
// languages emit the same JSON. Node and edge type strings match graph schema
// v0; see the constants in this package.
package collector

// SchemaVersion is the graph batch contract this SDK emits and accepts.
const SchemaVersion = 1

// InternetNodeID is the stable id of the synthetic internet node.
const InternetNodeID = "internet:global"

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
	EdgeReachable = "REACHABLE"
	EdgeAssumes   = "ASSUMES"
	EdgeCanAccess = "CAN_ACCESS"
	EdgeAffects   = "AFFECTS"
	EdgeViolates  = "VIOLATES"
)

// Node is one vertex in a collector batch.
type Node struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Provider   string         `json:"provider,omitempty"`
	Region     string         `json:"region,omitempty"`
	AccountID  string         `json:"account_id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Edge is one relationship in a collector batch.
type Edge struct {
	ID         string         `json:"id,omitempty"`
	SourceID   string         `json:"source_id"`
	TargetID   string         `json:"target_id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Batch is the JSON document a plugin writes to stdout.
type Batch struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// EdgeID builds the default edge id used when a plugin leaves ID empty.
func EdgeID(sourceID, targetID, edgeType string) string {
	return sourceID + "|" + targetID + "|" + edgeType
}
