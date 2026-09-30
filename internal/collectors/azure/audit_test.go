// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/OpenSourceOM/core/internal/graph"
)

const (
	auditSub       = "00000000-0000-0000-0000-000000000000"
	auditOtherSub  = "99999999-9999-9999-9999-999999999999"
	auditPrincipal = "11111111-1111-1111-1111-111111111111"
	auditVMID      = "/subscriptions/" + auditSub + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"
	auditStorageID = "/subscriptions/" + auditSub + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
	auditNSGID     = "/subscriptions/" + auditSub + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web"
)

func TestAttachAuditEventsLinksVMWriteOnExposedPath(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	web := c.nodeID("workload", "web")
	identity := c.nodeID("identity", auditPrincipal)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	event := activityEvent("evt-vm", "Microsoft.Compute/virtualMachines/write", auditVMID, when)
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{{event, event}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	webEvents := eventsOn(&batch, web)
	identityEvents := eventsOn(&batch, identity)
	if len(webEvents) != 1 || len(identityEvents) != 1 {
		t.Fatalf("web events = %d, identity events = %d, want one each", len(webEvents), len(identityEvents))
	}
	if webEvents[0].ID != "evt-vm" || webEvents[0].ResourceNodeID != web || webEvents[0].PrincipalNodeID != identity {
		t.Fatalf("event = %+v", webEvents[0])
	}
	if webEvents[0].ReadOnly || webEvents[0].SourceIP != "203.0.113.9" || webEvents[0].Principal != "alice@contoso.com" {
		t.Fatalf("event = %+v", webEvents[0])
	}
	if client.calls != 1 {
		t.Fatalf("lookups = %d, want 1", client.calls)
	}
	if !client.since.Equal(client.until.Add(-auditLookupWindow)) {
		t.Fatalf("window = %s to %s", client.since, client.until)
	}
}

func TestAttachAuditEventsSkipsUnexposedVM(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	batch.Edges = nil
	for i := range batch.Nodes {
		if batch.Nodes[i].Properties != nil {
			delete(batch.Nodes[i].Properties, "public_access")
		}
	}
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{
		{activityEvent("evt-vm", "Microsoft.Compute/virtualMachines/write", auditVMID, when)},
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
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	client := &fakeActivity{err: errors.New("access denied")}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events after a failed lookup", n)
	}
}

func TestAttachAuditEventsFollowsPagesAndCaps(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	web := c.nodeID("workload", "web")
	base := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	var first, second []*armmonitor.EventData
	for i := 0; i < 3; i++ {
		first = append(first, activityEvent(fmt.Sprintf("evt-%d", i), "Microsoft.Compute/virtualMachines/write", auditVMID, base.Add(time.Duration(i)*time.Minute)))
	}
	for i := 3; i < 6; i++ {
		second = append(second, activityEvent(fmt.Sprintf("evt-%d", i), "Microsoft.Compute/virtualMachines/write", auditVMID, base.Add(time.Duration(i)*time.Minute)))
	}
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{first, second}}}

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
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	pager := &scriptedPager{endless: true}
	client := &fakeActivity{pager: pager}

	c.attachAuditEvents(context.Background(), client, &batch)

	if pager.n != auditMaxPages {
		t.Fatalf("pages = %d, want the page cap %d", pager.n, auditMaxPages)
	}
}

func TestAttachAuditEventsKeepsPublicStorageChange(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	logs := c.nodeID("datastore", "logs")
	when := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{
		{activityEvent("evt-storage", "microsoft.storage/storageAccounts/write", strings.ToLower(auditStorageID), when)},
	}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	got := eventsOn(&batch, logs)
	if len(got) != 1 || got[0].Name != "microsoft.storage/storageAccounts/write" || got[0].ResourceNodeID != logs {
		t.Fatalf("storage events = %+v", got)
	}
}

func TestAttachAuditEventsWalksChildResources(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	nsg := c.nodeID("network", "web")
	logs := c.nodeID("datastore", "logs")
	when := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	rule := activityEvent("evt-rule", "Microsoft.Network/networkSecurityGroups/securityRules/write", auditNSGID+"/securityRules/allow-ssh", when)
	assignmentID := "/subscriptions/" + auditSub + "/providers/Microsoft.Authorization/roleAssignments/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	assignment := activityEvent("evt-role", "Microsoft.Authorization/roleAssignments/write", assignmentID, when.Add(time.Minute))
	scope := auditStorageID
	action := "Microsoft.Authorization/roleAssignments/write"
	assignment.Authorization = &armmonitor.SenderAuthorization{Scope: &scope, Action: &action}

	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{{rule, assignment}}}}
	c.attachAuditEvents(context.Background(), client, &batch)

	rules := eventsOn(&batch, nsg)
	if len(rules) != 1 || rules[0].ID != "evt-rule" || rules[0].Resource != auditNSGID+"/securityRules/allow-ssh" {
		t.Fatalf("nsg events = %+v", rules)
	}
	roles := eventsOn(&batch, logs)
	if len(roles) != 1 || roles[0].ID != "evt-role" || roles[0].Resource != auditStorageID {
		t.Fatalf("storage events = %+v", roles)
	}
}

func TestAttachAuditEventsDropsDataPlaneAndOtherSubscriptions(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	data := activityEvent("evt-data", "Microsoft.Storage/storageAccounts/listKeys/action", auditStorageID, when)
	other := activityEvent("evt-other", "Microsoft.Storage/storageAccounts/write", auditStorageID, when)
	otherSub := auditOtherSub
	other.SubscriptionID = &otherSub
	emailOnly := activityEvent("evt-email", "Microsoft.Compute/virtualMachines/write", auditVMID, when)
	emailOnly.Claims = nil
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{{data, other, emailOnly}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	if n := countAuditEvents(&batch); n != 0 {
		t.Fatalf("stored %d events that should not match", n)
	}
}

func TestAttachAuditEventsUsesCallerObjectID(t *testing.T) {
	c := NewCollector(auditSub, "eastus")
	batch := exposedAuditBatch(c)
	when := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	event := activityEvent("evt-mi", "Microsoft.Compute/virtualMachines/write", auditVMID, when)
	event.Claims = nil
	event.Caller = ptr(auditPrincipal)
	client := &fakeActivity{pager: &scriptedPager{pages: [][]*armmonitor.EventData{{event}}}}

	c.attachAuditEvents(context.Background(), client, &batch)

	if len(eventsOn(&batch, c.nodeID("workload", "web"))) != 1 {
		t.Fatal("object id caller was not attached")
	}
}

func TestActivityFilterIsSubscriptionWindow(t *testing.T) {
	since := time.Date(2026, 9, 29, 15, 4, 5, 0, time.FixedZone("EDT", -4*60*60))
	until := time.Date(2026, 9, 30, 15, 4, 5, 0, time.UTC)
	got := activityFilter(since, until)
	want := "eventTimestamp ge '2026-09-29T19:04:05.0000000Z' and eventTimestamp le '2026-09-30T15:04:05.0000000Z'"
	if got != want {
		t.Fatalf("filter = %q", got)
	}
}

func exposedAuditBatch(c *Collector) graph.Batch {
	return graph.Batch{
		Nodes: []graph.Node{
			{
				ID: c.nodeID("workload", "web"), Type: graph.NodeWorkload, Name: "web",
				Properties: map[string]any{"resource_id": auditVMID},
			},
			{
				ID: c.nodeID("datastore", "logs"), Type: graph.NodeDatastore, Name: "logs",
				Properties: map[string]any{"resource_id": auditStorageID, "public_access": true},
			},
			{
				ID: c.nodeID("identity", auditPrincipal), Type: graph.NodeIdentity, Name: auditPrincipal,
			},
			{
				ID: c.nodeID("network", "web"), Type: graph.NodeNetwork, Name: "web",
				Properties: map[string]any{"resource_id": auditNSGID},
			},
		},
		Edges: []graph.Edge{
			{SourceID: graph.InternetNodeID, TargetID: c.nodeID("workload", "web"), Type: graph.EdgeReachable},
			{SourceID: c.nodeID("workload", "web"), TargetID: c.nodeID("identity", auditPrincipal), Type: graph.EdgeAssumes},
			{SourceID: c.nodeID("identity", auditPrincipal), TargetID: c.nodeID("datastore", "logs"), Type: graph.EdgeCanAccess},
			{SourceID: c.nodeID("workload", "web"), TargetID: c.nodeID("network", "web"), Type: graph.EdgeAffects},
		},
	}
}

func activityEvent(id, operation, resource string, when time.Time) *armmonitor.EventData {
	sub := auditSub
	caller := "alice@contoso.com"
	oid := auditPrincipal
	method := "PUT"
	ip := "203.0.113.9"
	return &armmonitor.EventData{
		EventDataID:    &id,
		OperationName:  &armmonitor.LocalizableString{Value: &operation},
		EventTimestamp: &when,
		Caller:         &caller,
		SubscriptionID: &sub,
		ResourceID:     &resource,
		Claims: map[string]*string{
			objectIDClaim: &oid,
		},
		HTTPRequest: &armmonitor.HTTPRequestInfo{ClientIPAddress: &ip, Method: &method},
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

type fakeActivity struct {
	pager        activityPager
	err          error
	calls        int
	since, until time.Time
}

func (f *fakeActivity) ListPager(since, until time.Time) (activityPager, error) {
	f.calls++
	f.since = since
	f.until = until
	if f.err != nil {
		return nil, f.err
	}
	return f.pager, nil
}

type scriptedPager struct {
	pages   [][]*armmonitor.EventData
	n       int
	endless bool
}

func (p *scriptedPager) More() bool {
	if p.endless {
		return true
	}
	return p.n < len(p.pages)
}

func (p *scriptedPager) NextPage(context.Context) ([]*armmonitor.EventData, error) {
	p.n++
	if p.endless {
		return nil, nil
	}
	return p.pages[p.n-1], nil
}
