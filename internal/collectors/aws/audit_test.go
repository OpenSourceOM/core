// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

func TestAttachAuditEventsLinksAssumeRoleOnExposedPath(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	role := c.globalNodeID("identity", "Admin")
	user := c.globalNodeID("identity", "user/alice")
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeTrail{
		pages: map[string][]trailtypes.Event{
			"": {assumeRoleEvent("evt-assume", when, "arn:aws:iam::111122223333:user/alice", "arn:aws:iam::111122223333:role/Admin")},
		},
	}

	c.attachAuditEvents(context.Background(), client, &batch)

	roleEvents := eventsOn(&batch, role)
	userEvents := eventsOn(&batch, user)
	if len(roleEvents) != 1 || len(userEvents) != 1 {
		t.Fatalf("role events = %d, user events = %d, want both", len(roleEvents), len(userEvents))
	}
	if roleEvents[0].ID != "evt-assume" || roleEvents[0].ResourceNodeID != role || roleEvents[0].PrincipalNodeID != user {
		t.Fatalf("event = %+v", roleEvents[0])
	}
	if roleEvents[0].ReadOnly {
		t.Fatal("AssumeRole stored as read-only")
	}
	if client.regions[0] != "us-east-1" || len(client.regions) != 1 {
		t.Fatalf("regions = %v, want one us-east-1 lookup", client.regions)
	}
}

func TestAttachAuditEventsSkipsUnexposedRole(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	batch.Edges = nil
	for i := range batch.Nodes {
		if batch.Nodes[i].Properties != nil {
			delete(batch.Nodes[i].Properties, "public_access")
		}
	}
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeTrail{pages: map[string][]trailtypes.Event{
		"": {assumeRoleEvent("evt-assume", when, "arn:aws:iam::111122223333:user/alice", "arn:aws:iam::111122223333:role/Admin")},
	}}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events on a graph with no exposed path", n)
	}
}

func TestAttachAuditEventsOmitsOnLookupError(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	client := &fakeTrail{err: errors.New("access denied")}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events after a failed lookup", n)
	}
}

func TestAttachAuditEventsFollowsPagesAndCaps(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	role := c.globalNodeID("identity", "Admin")
	user := "arn:aws:iam::111122223333:user/alice"
	roleARN := "arn:aws:iam::111122223333:role/Admin"
	base := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	var first, second []trailtypes.Event
	for i := 0; i < 3; i++ {
		first = append(first, assumeRoleEvent(fmt.Sprintf("evt-%d", i), base.Add(time.Duration(i)*time.Minute), user, roleARN))
	}
	for i := 3; i < 6; i++ {
		second = append(second, assumeRoleEvent(fmt.Sprintf("evt-%d", i), base.Add(time.Duration(i)*time.Minute), user, roleARN))
	}
	client := &fakeTrail{
		pages: map[string][]trailtypes.Event{"": first, "page-2": second},
		next:  map[string]string{"": "page-2"},
	}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, role)
	if len(got) != auditMaxPerNode {
		t.Fatalf("events = %d, want the cap %d", len(got), auditMaxPerNode)
	}
	if got[0].ID != "evt-5" || got[len(got)-1].ID != "evt-1" {
		t.Fatalf("order = %s then %s, want newest evt-5 down to evt-1", got[0].ID, got[len(got)-1].ID)
	}
}

func TestAttachAuditEventsStopsPaging(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	client := &fakeTrail{endless: true}

	c.attachAuditEvents(context.Background(), client, &batch)

	if client.calls != auditMaxPages {
		t.Fatalf("calls = %d, want the page cap %d", client.calls, auditMaxPages)
	}
}

func TestAttachAuditEventsLooksUpGlobalEvents(t *testing.T) {
	c := &Collector{Region: "eu-west-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeTrail{
		pages: map[string][]trailtypes.Event{
			"us-east-1": {assumeRoleEvent("evt-global", when, "arn:aws:iam::111122223333:user/alice", "arn:aws:iam::111122223333:role/Admin")},
		},
	}

	c.attachAuditEvents(context.Background(), client, &batch)

	if strings.Join(client.regions, ",") != "eu-west-1,us-east-1" {
		t.Fatalf("regions = %v", client.regions)
	}
	if len(eventsOn(&batch, c.globalNodeID("identity", "Admin"))) != 1 {
		t.Fatal("us-east-1 AssumeRole was not attached")
	}
}

func TestAttachAuditEventsKeepsPublicBucketChange(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	bucket := c.globalNodeID("datastore", "logs")
	when := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	payload := `{"userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice","accountId":"111122223333"},"sourceIPAddress":"203.0.113.9","requestParameters":{"bucketName":"logs"}}`
	client := &fakeTrail{pages: map[string][]trailtypes.Event{
		"": {{
			EventId:         aws.String("evt-policy"),
			EventName:       aws.String("PutBucketPolicy"),
			EventTime:       &when,
			ReadOnly:        aws.String("false"),
			CloudTrailEvent: aws.String(payload),
		}},
	}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, bucket)
	if len(got) != 1 || got[0].Name != "PutBucketPolicy" || got[0].ResourceNodeID != bucket {
		t.Fatalf("bucket events = %+v", got)
	}
}

func TestAttachAuditEventsDropsDataEventsAndOtherAccounts(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeTrail{pages: map[string][]trailtypes.Event{
		"": {
			assumeRoleEvent("evt-data", when, "arn:aws:iam::111122223333:user/alice", "arn:aws:iam::111122223333:role/Admin"),
			assumeRoleEvent("evt-other", when, "arn:aws:iam::999999999999:user/alice", "arn:aws:iam::999999999999:role/Admin"),
		},
	}}
	client.pages[""][0].EventName = aws.String("GetObject")

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events, want data events and other accounts dropped", n)
	}
}

func TestAttachAuditEventsMapsAssumedRoleSession(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	batch := exposedAuditBatch(c)
	role := c.globalNodeID("identity", "Admin")
	bucket := c.globalNodeID("datastore", "logs")
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	payload := `{"userIdentity":{"arn":"arn:aws:sts::111122223333:assumed-role/Admin/i-1","accountId":"111122223333","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::111122223333:role/Admin"}}},"requestParameters":{"bucketName":"logs"}}`
	client := &fakeTrail{pages: map[string][]trailtypes.Event{
		"": {{
			EventId:         aws.String("evt-session"),
			EventName:       aws.String("PutBucketAcl"),
			EventTime:       &when,
			CloudTrailEvent: aws.String(payload),
		}},
	}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, bucket)
	if len(got) != 1 || got[0].PrincipalNodeID != role || got[0].ResourceNodeID != bucket {
		t.Fatalf("event = %+v", got)
	}
}

func exposedAuditBatch(c *Collector) graph.Batch {
	workload := c.nodeID("workload", "i-1")
	role := c.globalNodeID("identity", "Admin")
	user := c.globalNodeID("identity", "user/alice")
	bucket := c.globalNodeID("datastore", "logs")
	return graph.Batch{
		Nodes: []graph.Node{
			{ID: graph.InternetNodeID, Type: graph.NodeInternet, Name: "Internet"},
			{ID: workload, Type: graph.NodeWorkload, Name: "web", Provider: "aws", Properties: map[string]any{"resource_id": "i-1"}},
			{ID: role, Type: graph.NodeIdentity, Name: "Admin", Provider: "aws", Properties: map[string]any{
				"arn": "arn:aws:iam::111122223333:role/Admin", "principal_type": "role",
			}},
			{ID: user, Type: graph.NodeIdentity, Name: "alice", Provider: "aws", Properties: map[string]any{
				"arn": "arn:aws:iam::111122223333:user/alice", "principal_type": "user",
			}},
			{ID: bucket, Type: graph.NodeDatastore, Name: "logs", Provider: "aws", Properties: map[string]any{
				"service": "s3", "resource_id": "logs", "public_access": true,
			}},
		},
		Edges: []graph.Edge{
			{SourceID: graph.InternetNodeID, TargetID: workload, Type: graph.EdgeReachable},
			{SourceID: workload, TargetID: role, Type: graph.EdgeAssumes},
			{SourceID: role, TargetID: bucket, Type: graph.EdgeCanAccess},
		},
	}
}

func assumeRoleEvent(id string, when time.Time, principal, role string) trailtypes.Event {
	payload := fmt.Sprintf(`{"userIdentity":{"arn":%q,"accountId":%q},"sourceIPAddress":"203.0.113.4","requestParameters":{"roleArn":%q}}`, principal, arnField(principal, 4), role)
	return trailtypes.Event{
		EventId:         aws.String(id),
		EventName:       aws.String("AssumeRole"),
		EventTime:       &when,
		ReadOnly:        aws.String("false"),
		CloudTrailEvent: aws.String(payload),
		Resources: []trailtypes.Resource{{
			ResourceName: aws.String(role),
			ResourceType: aws.String("AWS::IAM::Role"),
		}},
	}
}

func eventsOn(batch *graph.Batch, id string) []graph.AuditEvent {
	for _, node := range batch.Nodes {
		if node.ID == id {
			return graph.AuditEventsFrom(node.Properties)
		}
	}
	return nil
}

func countAuditEvents(batch *graph.Batch) int {
	n := 0
	for _, node := range batch.Nodes {
		n += len(graph.AuditEventsFrom(node.Properties))
	}
	return n
}

type fakeTrail struct {
	pages   map[string][]trailtypes.Event
	next    map[string]string
	err     error
	endless bool
	regions []string
	calls   int
}

func (f *fakeTrail) LookupEvents(_ context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.calls++
	opts := cloudtrail.Options{}
	for _, fn := range optFns {
		fn(&opts)
	}
	f.regions = append(f.regions, opts.Region)
	if f.err != nil {
		return nil, f.err
	}
	if f.endless {
		token := "more"
		return &cloudtrail.LookupEventsOutput{NextToken: &token}, nil
	}
	key := ""
	if params != nil && params.NextToken != nil {
		key = *params.NextToken
	}
	if opts.Region == "us-east-1" {
		if events, ok := f.pages["us-east-1"]; ok && key == "" {
			return &cloudtrail.LookupEventsOutput{Events: events}, nil
		}
	}
	out := &cloudtrail.LookupEventsOutput{Events: f.pages[key]}
	if next := f.next[key]; next != "" {
		out.NextToken = aws.String(next)
	}
	return out, nil
}
