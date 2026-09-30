// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

func TestFinishPathsIncludesAudits(t *testing.T) {
	props := map[string]any{}
	SetAuditEvents(props, []AuditEvent{{
		ID:             "evt-1",
		Name:           "AssumeRole",
		ResourceNodeID: "role",
	}})
	paths := [][]Node{{
		{ID: InternetNodeID, Type: NodeInternet, Name: "Internet"},
		{ID: "role", Type: NodeIdentity, Name: "Admin", Properties: props},
	}}
	result := finishPaths("internet-to-workload", "summary", paths, 50, false)
	if len(result.Audits) != 1 || len(result.Audits[0].Events) != 1 || result.Audits[0].Events[0].ID != "evt-1" {
		t.Fatalf("audits = %+v", result.Audits)
	}
	if result.Audits[0].Index != 0 {
		t.Fatalf("index = %d", result.Audits[0].Index)
	}
}
