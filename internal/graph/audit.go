// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "encoding/json"

// AuditEventsProperty is the node property that holds recent cloud audit
// events attached to an identity or resource. The AWS and Azure collectors
// write it. A plugin may set the same shape. The GCP collector does not.
const AuditEventsProperty = "audit_events"

// AuditEvent is one management event attached to existing graph nodes.
// It is evidence that a principal acted on a resource, not a new node type.
type AuditEvent struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Time            string `json:"time"`
	Principal       string `json:"principal,omitempty"`
	Resource        string `json:"resource,omitempty"`
	PrincipalNodeID string `json:"principal_node_id,omitempty"`
	ResourceNodeID  string `json:"resource_node_id,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	ReadOnly        bool   `json:"read_only"`
}

// PathAudit is the set of audit events whose resource node sits on Paths[Index].
type PathAudit struct {
	Index  int          `json:"index"`
	Events []AuditEvent `json:"events"`
}

// SetAuditEvents stores events on props. An empty list removes the key.
func SetAuditEvents(props map[string]any, events []AuditEvent) {
	if props == nil {
		return
	}
	if len(events) == 0 {
		delete(props, AuditEventsProperty)
		return
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return
	}
	props[AuditEventsProperty] = decoded
}

// AuditEventsFrom reads events stored by SetAuditEvents.
// A missing or unreadable value returns nil.
func AuditEventsFrom(props map[string]any) []AuditEvent {
	if props == nil {
		return nil
	}
	raw, ok := props[AuditEventsProperty]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var events []AuditEvent
	if err := json.Unmarshal(encoded, &events); err != nil {
		return nil
	}
	return events
}

// AuditsForPaths returns events that show use of a returned path.
// An event is included when its resource node is on that path.
// The same event stored on two nodes of one path is returned once.
func AuditsForPaths(paths [][]Node) []PathAudit {
	var out []PathAudit
	for i, path := range paths {
		onPath := make(map[string]bool, len(path))
		for _, node := range path {
			onPath[node.ID] = true
		}
		seen := map[string]bool{}
		var events []AuditEvent
		for _, node := range path {
			for _, event := range AuditEventsFrom(node.Properties) {
				if event.ID == "" || seen[event.ID] {
					continue
				}
				if event.ResourceNodeID == "" || !onPath[event.ResourceNodeID] {
					continue
				}
				seen[event.ID] = true
				events = append(events, event)
			}
		}
		if len(events) == 0 {
			continue
		}
		out = append(out, PathAudit{Index: i, Events: events})
	}
	return out
}
