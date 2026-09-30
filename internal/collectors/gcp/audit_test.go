// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
)

const (
	auditProject   = "demo-project"
	auditEmail     = "web@demo-project.iam.gserviceaccount.com"
	auditInstance  = "https://www.googleapis.com/compute/v1/projects/demo-project/zones/us-central1-a/instances/web"
	auditBucket    = "logs"
	auditFirewall  = "https://www.googleapis.com/compute/v1/projects/demo-project/global/firewalls/allow-web"
	auditSQL       = "demo-project:us-central1:prod"
	auditOtherProj = "other-project"
)

func TestAttachAuditEventsLinksInstanceInsertOnExposedPath(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	web := c.nodeID("us-central1-a", "workload", "web")
	identity := c.nodeID("us-central1", "identity", "111")
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	resource := "projects/demo-project/zones/us-central1-a/instances/web"
	event := activityEntry("evt-vm", "compute.googleapis.com", "v1.compute.instances.insert", resource, when)
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{{event, event}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	webEvents := eventsOn(&batch, web)
	identityEvents := eventsOn(&batch, identity)
	if len(webEvents) != 1 || len(identityEvents) != 1 {
		t.Fatalf("web events = %d, identity events = %d, want one each", len(webEvents), len(identityEvents))
	}
	if webEvents[0].ID != "evt-vm" || webEvents[0].ResourceNodeID != web || webEvents[0].PrincipalNodeID != identity {
		t.Fatalf("event = %+v", webEvents[0])
	}
	if webEvents[0].ReadOnly || webEvents[0].SourceIP != "203.0.113.9" || webEvents[0].Principal != auditEmail {
		t.Fatalf("event = %+v", webEvents[0])
	}
	if webEvents[0].Name != "v1.compute.instances.insert" || webEvents[0].Resource != resource {
		t.Fatalf("event = %+v", webEvents[0])
	}
	if client.calls != 1 {
		t.Fatalf("lookups = %d, want 1", client.calls)
	}
	wantSince := time.Now().UTC().Add(-auditLookupWindow)
	if client.since.Before(wantSince.Add(-time.Minute)) || client.since.After(wantSince.Add(time.Minute)) {
		t.Fatalf("since = %s, want about %s", client.since, wantSince)
	}
}

func TestAttachAuditEventsSkipsUnexposedInstance(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	batch.Edges = nil
	for i := range batch.Nodes {
		if batch.Nodes[i].Properties != nil {
			delete(batch.Nodes[i].Properties, "public_access")
		}
	}
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{
		{activityEntry("evt-vm", "compute.googleapis.com", "v1.compute.instances.insert", "projects/demo-project/zones/us-central1-a/instances/web", when)},
	}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events on a graph with no exposed path", n)
	}
	if client.calls != 0 {
		t.Fatalf("lookups = %d, want none when nothing is exposed", client.calls)
	}
}

func TestAttachAuditEventsOmitsOnLookupError(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	client := &fakeLogging{err: errors.New("access denied")}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events after a failed lookup", n)
	}
}

func TestAttachAuditEventsFollowsPagesAndCaps(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	web := c.nodeID("us-central1-a", "workload", "web")
	base := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	resource := "projects/demo-project/zones/us-central1-a/instances/web"
	var first, second []auditEntry
	for i := 0; i < 3; i++ {
		first = append(first, activityEntry(fmt.Sprintf("evt-%d", i), "compute.googleapis.com", "v1.compute.instances.insert", resource, base.Add(time.Duration(i)*time.Minute)))
	}
	for i := 3; i < 6; i++ {
		second = append(second, activityEntry(fmt.Sprintf("evt-%d", i), "compute.googleapis.com", "beta.compute.instances.insert", resource, base.Add(time.Duration(i)*time.Minute)))
	}
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{first, second}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, web)
	if len(got) != auditMaxPerNode {
		t.Fatalf("events = %d, want the cap %d", len(got), auditMaxPerNode)
	}
	if got[0].ID != "evt-5" || got[len(got)-1].ID != "evt-1" {
		t.Fatalf("order = %s then %s, want newest evt-5 down to evt-1", got[0].ID, got[len(got)-1].ID)
	}
}

func TestAttachAuditEventsStopsPaging(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	pager := &scriptedPager{endless: true}
	client := &fakeLogging{pager: pager}

	c.attachAuditEvents(context.Background(), client, &batch)

	if pager.n != auditMaxPages {
		t.Fatalf("pages = %d, want the page cap %d", pager.n, auditMaxPages)
	}
}

func TestAttachAuditEventsKeepsPublicBucketChange(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	logs := c.nodeID("us-central1", "datastore", "logs")
	when := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	resource := "projects/_/buckets/logs"
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{
		{activityEntry("evt-bucket", "storage.googleapis.com", "storage.buckets.update", resource, when)},
	}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, logs)
	if len(got) != 1 || got[0].Name != "storage.buckets.update" || got[0].ResourceNodeID != logs || got[0].Resource != resource {
		t.Fatalf("bucket events = %+v", got)
	}
}

func TestAttachAuditEventsWalksChildResources(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	firewall := c.nodeID("global", "network", "allow-web")
	identity := c.nodeID("us-central1", "identity", "111")
	when := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	rule := "projects/demo-project/global/firewalls/allow-web"
	key := "projects/demo-project/serviceAccounts/" + auditEmail + "/keys/1"
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{{
		activityEntry("evt-fw", "compute.googleapis.com", "v1.compute.firewalls.patch", rule, when),
		activityEntry("evt-key", "iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey", key, when.Add(time.Minute)),
	}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	rules := eventsOn(&batch, firewall)
	if len(rules) != 1 || rules[0].ID != "evt-fw" || rules[0].Resource != rule {
		t.Fatalf("firewall events = %+v", rules)
	}
	keys := eventsOn(&batch, identity)
	found := false
	for _, event := range keys {
		if event.ID == "evt-key" && event.ResourceNodeID == identity && event.Resource == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity events = %+v", keys)
	}
}

func TestAttachAuditEventsKeepsCloudSQLUpdate(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	prod := c.nodeID("us-central1", "datastore", "prod")
	when := time.Date(2026, 9, 30, 17, 0, 0, 0, time.UTC)
	resource := "projects/demo-project/instances/prod"
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{
		{activityEntry("evt-sql", "sqladmin.googleapis.com", "cloudsql.instances.update", resource, when)},
	}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, prod)
	if len(got) != 1 || got[0].ResourceNodeID != prod || got[0].Name != "cloudsql.instances.update" {
		t.Fatalf("sql events = %+v", got)
	}
}

func TestAttachAuditEventsUsesProjectIAMOnThePrincipal(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	identity := c.nodeID("us-central1", "identity", "111")
	when := time.Date(2026, 9, 30, 18, 0, 0, 0, time.UTC)
	event := activityEntry("evt-iam", "cloudresourcemanager.googleapis.com", "SetIamPolicy", "projects/"+auditProject, when)
	event = withSubject(event, "serviceAccount:"+auditEmail)
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{{event}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, identity)
	if len(got) != 1 || got[0].ResourceNodeID != identity || got[0].Name != "SetIamPolicy" {
		t.Fatalf("iam events = %+v", got)
	}
}

func TestAttachAuditEventsDropsDataAccessAndOtherProjects(t *testing.T) {
	c := NewCollector(auditProject, "us-central1")
	batch := exposedAuditBatch(c)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	data := activityEntry("evt-data", "storage.googleapis.com", "storage.objects.get", "projects/_/buckets/logs/objects/secret", when)
	other := activityEntry("evt-other", "compute.googleapis.com", "v1.compute.instances.insert", "projects/"+auditOtherProj+"/zones/us-central1-a/instances/web", when)
	user := activityEntry("evt-user", "compute.googleapis.com", "v1.compute.instances.insert", "projects/demo-project/zones/us-central1-a/instances/web", when)
	user = withPrincipal(user, "alice@example.com", "")
	dataAccessLog := activityEntry("evt-log", "compute.googleapis.com", "v1.compute.instances.insert", "projects/demo-project/zones/us-central1-a/instances/web", when)
	dataAccessLog.LogName = "projects/" + auditProject + "/logs/cloudaudit.googleapis.com%2Fdata_access"
	client := &fakeLogging{pager: &scriptedPager{pages: [][]auditEntry{{data, other, user, dataAccessLog}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events that should not match", n)
	}
}

func TestAuditFilterIsProjectWindow(t *testing.T) {
	since := time.Date(2026, 9, 29, 15, 4, 5, 0, time.FixedZone("EDT", -4*60*60))
	got := auditFilter(auditProject, since)
	want := `logName="projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp>="2026-09-29T19:04:05Z"`
	if got != want {
		t.Fatalf("filter = %q", got)
	}
}

func exposedAuditBatch(c *Collector) graph.Batch {
	return graph.Batch{
		Nodes: []graph.Node{
			{
				ID: c.nodeID("us-central1-a", "workload", "web"), Type: graph.NodeWorkload, Name: "web",
				Properties: map[string]any{"resource_id": auditInstance},
			},
			{
				ID: c.nodeID("us-central1", "datastore", "logs"), Type: graph.NodeDatastore, Name: "logs",
				Properties: map[string]any{"resource_id": auditBucket, "public_access": true},
			},
			{
				ID: c.nodeID("us-central1", "identity", "111"), Type: graph.NodeIdentity, Name: auditEmail,
				Properties: map[string]any{"email": auditEmail},
			},
			{
				ID: c.nodeID("global", "network", "allow-web"), Type: graph.NodeNetwork, Name: "allow-web",
				Properties: map[string]any{"resource_id": auditFirewall},
			},
			{
				ID: c.nodeID("us-central1", "datastore", "prod"), Type: graph.NodeDatastore, Name: "prod",
				Properties: map[string]any{"resource_id": auditSQL, "service": "cloudsql"},
			},
		},
		Edges: []graph.Edge{
			{SourceID: graph.InternetNodeID, TargetID: c.nodeID("us-central1-a", "workload", "web"), Type: graph.EdgeReachable},
			{SourceID: c.nodeID("us-central1-a", "workload", "web"), TargetID: c.nodeID("us-central1", "identity", "111"), Type: graph.EdgeAssumes},
			{SourceID: c.nodeID("us-central1", "identity", "111"), TargetID: c.nodeID("us-central1", "datastore", "logs"), Type: graph.EdgeCanAccess},
			{SourceID: c.nodeID("us-central1-a", "workload", "web"), TargetID: c.nodeID("global", "network", "allow-web"), Type: graph.EdgeAffects},
			{SourceID: c.nodeID("us-central1-a", "workload", "web"), TargetID: c.nodeID("us-central1", "datastore", "prod"), Type: graph.EdgeCanAccess},
		},
	}
}

func activityEntry(id, service, method, resource string, when time.Time) auditEntry {
	payload := auditPayload{
		ServiceName:  service,
		MethodName:   method,
		ResourceName: resource,
	}
	payload.AuthenticationInfo.PrincipalEmail = auditEmail
	payload.RequestMetadata.CallerIP = "203.0.113.9"
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return auditEntry{
		InsertID:     id,
		Timestamp:    when.UTC().Format(time.RFC3339Nano),
		ProtoPayload: raw,
		LogName:      "projects/" + auditProject + "/logs/cloudaudit.googleapis.com%2Factivity",
	}
}

func withPrincipal(entry auditEntry, email, subject string) auditEntry {
	var payload auditPayload
	if err := json.Unmarshal(entry.ProtoPayload, &payload); err != nil {
		panic(err)
	}
	payload.AuthenticationInfo.PrincipalEmail = email
	payload.AuthenticationInfo.PrincipalSubject = subject
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	entry.ProtoPayload = raw
	return entry
}

func withSubject(entry auditEntry, subject string) auditEntry {
	return withPrincipal(entry, "", subject)
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

type fakeLogging struct {
	pager auditPager
	err   error
	calls int
	since time.Time
}

func (f *fakeLogging) ListPager(since time.Time) (auditPager, error) {
	f.calls++
	f.since = since
	if f.err != nil {
		return nil, f.err
	}
	return f.pager, nil
}

type scriptedPager struct {
	pages   [][]auditEntry
	n       int
	endless bool
}

func (p *scriptedPager) More() bool {
	if p.endless {
		return true
	}
	return p.n < len(p.pages)
}

func (p *scriptedPager) NextPage(context.Context) ([]auditEntry, error) {
	p.n++
	if p.endless {
		return nil, nil
	}
	return p.pages[p.n-1], nil
}
