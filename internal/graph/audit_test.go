// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestAuditsForPathsKeepsEventsOnTheResource(t *testing.T) {
	roleID := "aws:111:global:identity:Admin"
	bucketID := "aws:111:global:datastore:logs"
	otherID := "aws:111:global:datastore:private"
	event := graph.AuditEvent{
		ID:              "evt-assume",
		Name:            "AssumeRole",
		Time:            "2026-09-30T15:00:00Z",
		Principal:       "arn:aws:iam::111:user/alice",
		Resource:        "arn:aws:iam::111:role/Admin",
		PrincipalNodeID: "aws:111:global:identity:user/alice",
		ResourceNodeID:  roleID,
	}
	bucketEvent := graph.AuditEvent{
		ID:             "evt-policy",
		Name:           "PutBucketPolicy",
		Time:           "2026-09-30T15:04:00Z",
		Resource:       "arn:aws:s3:::logs",
		ResourceNodeID: bucketID,
	}

	roleProps := map[string]any{}
	graph.SetAuditEvents(roleProps, []graph.AuditEvent{event})
	bucketProps := map[string]any{}
	graph.SetAuditEvents(bucketProps, []graph.AuditEvent{event, bucketEvent})

	paths := [][]graph.Node{
		{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: roleID, Type: graph.NodeIdentity, Name: "Admin", Properties: roleProps},
			{ID: bucketID, Type: graph.NodeDatastore, Name: "logs", Properties: bucketProps},
		},
		{
			{ID: otherID, Type: graph.NodeDatastore, Name: "private"},
		},
	}

	got := graph.AuditsForPaths(paths)
	if len(got) != 1 {
		t.Fatalf("audits = %d, want the exposed path only", len(got))
	}
	if got[0].Index != 0 {
		t.Fatalf("index = %d, want 0", got[0].Index)
	}
	if len(got[0].Events) != 2 {
		t.Fatalf("events = %d, want AssumeRole once and PutBucketPolicy", len(got[0].Events))
	}
	if got[0].Events[0].ID != "evt-assume" || got[0].Events[1].ID != "evt-policy" {
		t.Fatalf("events = %+v", got[0].Events)
	}
}

func TestSetAuditEventsRoundTrip(t *testing.T) {
	props := map[string]any{}
	graph.SetAuditEvents(props, nil)
	if _, ok := props[graph.AuditEventsProperty]; ok {
		t.Fatal("empty events left the property set")
	}
	graph.SetAuditEvents(props, []graph.AuditEvent{{
		ID:       "evt-1",
		Name:     "AssumeRole",
		ReadOnly: false,
	}})
	got := graph.AuditEventsFrom(props)
	if len(got) != 1 || got[0].ID != "evt-1" || got[0].Name != "AssumeRole" || got[0].ReadOnly {
		t.Fatalf("events = %+v", got)
	}
}
