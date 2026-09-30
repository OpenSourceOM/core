// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/OpenSourceOM/core/internal/graph"
)

const (
	auditLookupWindow  = 24 * time.Hour
	auditMaxPages      = 4
	auditMaxPerNode    = 5
	activityTimeLayout = "2006-01-02T15:04:05.0000000Z"
	objectIDClaim      = "http://schemas.microsoft.com/identity/claims/objectidentifier"
)

// auditOperationNames are administrative operations that show a principal
// changing an identity, datastore, workload, or network control.
// The Activity Log API does not return storage data-plane reads, and Entra
// ID sign-in logs are a different source.
var auditOperationNames = map[string]struct{}{
	"microsoft.compute/virtualmachines/write":                         {},
	"microsoft.network/networksecuritygroups/write":                   {},
	"microsoft.network/networksecuritygroups/securityrules/write":     {},
	"microsoft.network/networksecuritygroups/securityrules/delete":    {},
	"microsoft.network/publicipaddresses/write":                       {},
	"microsoft.network/publicipaddresses/delete":                      {},
	"microsoft.network/networkinterfaces/write":                       {},
	"microsoft.storage/storageaccounts/write":                         {},
	"microsoft.storage/storageaccounts/blobservices/containers/write": {},
	"microsoft.authorization/roleassignments/write":                   {},
	"microsoft.authorization/roleassignments/delete":                  {},
	"microsoft.sql/servers/write":                                     {},
	"microsoft.sql/servers/firewallrules/write":                       {},
	"microsoft.sql/servers/firewallrules/delete":                      {},
	"microsoft.sql/servers/virtualnetworkrules/write":                 {},
	"microsoft.sql/servers/virtualnetworkrules/delete":                {},
}

// activityPager is one page of Activity Log events.
type activityPager interface {
	More() bool
	NextPage(context.Context) ([]*armmonitor.EventData, error)
}

// activityLogAPI opens a paged Activity Log query. A nil client omits events.
type activityLogAPI interface {
	ListPager(since, until time.Time) (activityPager, error)
}

type armActivityLogs struct {
	client *armmonitor.ActivityLogsClient
}

func (c *Collector) activityLogs(cred azcore.TokenCredential) activityLogAPI {
	if cred == nil || c.SubscriptionID == "" {
		return nil
	}
	client, err := armmonitor.NewActivityLogsClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return nil
	}
	return &armActivityLogs{client: client}
}

func (a *armActivityLogs) ListPager(since, until time.Time) (activityPager, error) {
	if a == nil || a.client == nil {
		return nil, nil
	}
	pager := a.client.NewListPager(activityFilter(since, until), nil)
	return &sdkActivityPager{inner: pager}, nil
}

type sdkActivityPager struct {
	inner *runtime.Pager[armmonitor.ActivityLogsClientListResponse]
}

func (p *sdkActivityPager) More() bool {
	return p.inner.More()
}

func (p *sdkActivityPager) NextPage(ctx context.Context) ([]*armmonitor.EventData, error) {
	page, err := p.inner.NextPage(ctx)
	if err != nil {
		return nil, err
	}
	return page.Value, nil
}

func activityFilter(since, until time.Time) string {
	return fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'",
		since.UTC().Format(activityTimeLayout),
		until.UTC().Format(activityTimeLayout))
}

type matchedAudit struct {
	event graph.AuditEvent
	when  time.Time
}

// attachAuditEvents stores recent Activity Log events on the identity and
// resource nodes they name. A lookup error omits the property. Events are
// kept only when the resource sits on an exposed path in this batch:
// internet-reachable, assumed by such a workload, able to reach that
// workload's data, or a public datastore and the identities that can access it.
func (c *Collector) attachAuditEvents(ctx context.Context, client activityLogAPI, batch *graph.Batch) {
	if client == nil || batch == nil || c.SubscriptionID == "" {
		return
	}
	exposed := exposedNodeIDs(batch)
	if len(exposed) == 0 {
		return
	}
	until := time.Now().UTC()
	pager, err := client.ListPager(until.Add(-auditLookupWindow), until)
	if err != nil || pager == nil {
		return
	}
	events, _ := listActivityEvents(ctx, pager)
	index := buildAzureAuditIndex(batch)
	var matched []matchedAudit
	seen := map[string]bool{}
	for _, event := range events {
		item, ok := c.matchAuditEvent(event, index, exposed)
		if !ok || seen[item.event.ID] {
			continue
		}
		seen[item.event.ID] = true
		matched = append(matched, item)
	}
	if len(matched) == 0 {
		return
	}
	sortAuditsNewestFirst(matched)
	counts := map[string]int{}
	for _, item := range matched {
		addAuditEvent(batch, item.event.PrincipalNodeID, item.event, counts)
		if item.event.ResourceNodeID != item.event.PrincipalNodeID {
			addAuditEvent(batch, item.event.ResourceNodeID, item.event, counts)
		}
	}
}

func listActivityEvents(ctx context.Context, pager activityPager) ([]*armmonitor.EventData, error) {
	if pager == nil {
		return nil, nil
	}
	var events []*armmonitor.EventData
	for page := 0; page < auditMaxPages && pager.More(); page++ {
		batch, err := pager.NextPage(ctx)
		if err != nil {
			return events, err
		}
		events = append(events, batch...)
	}
	return events, nil
}

func (c *Collector) matchAuditEvent(event *armmonitor.EventData, index *azureAuditIndex, exposed map[string]bool) (matchedAudit, bool) {
	if event == nil || event.EventTimestamp == nil {
		return matchedAudit{}, false
	}
	name := operationName(event)
	if _, ok := auditOperationNames[strings.ToLower(name)]; !ok {
		return matchedAudit{}, false
	}
	id := strings.TrimSpace(safeString(event.EventDataID))
	if id == "" || !c.eventInSubscription(event) {
		return matchedAudit{}, false
	}
	principalID, ok := index.principal(event)
	if !ok {
		return matchedAudit{}, false
	}
	resourceRaw, resourceID, ok := index.resource(event, principalID, exposed)
	if !ok {
		return matchedAudit{}, false
	}
	principal := strings.TrimSpace(safeString(event.Caller))
	if principal == "" {
		principal = objectID(event)
	}
	return matchedAudit{
		when: event.EventTimestamp.UTC(),
		event: graph.AuditEvent{
			ID:              id,
			Name:            name,
			Time:            event.EventTimestamp.UTC().Format(time.RFC3339),
			Principal:       principal,
			Resource:        resourceRaw,
			PrincipalNodeID: principalID,
			ResourceNodeID:  resourceID,
			SourceIP:        clientIP(event),
			ReadOnly:        requestReadOnly(event),
		},
	}, true
}

func (c *Collector) eventInSubscription(event *armmonitor.EventData) bool {
	sub := strings.ToLower(strings.TrimSpace(c.SubscriptionID))
	if sub == "" {
		return false
	}
	if got := strings.ToLower(strings.TrimSpace(safeString(event.SubscriptionID))); got != "" {
		return got == sub
	}
	rid := strings.ToLower(safeString(event.ResourceID))
	return strings.Contains(rid, "/subscriptions/"+sub+"/")
}

func operationName(event *armmonitor.EventData) string {
	if event.OperationName == nil || event.OperationName.Value == nil {
		return ""
	}
	return strings.TrimSpace(*event.OperationName.Value)
}

func objectID(event *armmonitor.EventData) string {
	if id := claim(event.Claims, objectIDClaim); id != "" {
		return id
	}
	if id := claim(event.Claims, "oid"); id != "" {
		return id
	}
	caller := strings.TrimSpace(safeString(event.Caller))
	if isObjectID(caller) {
		return caller
	}
	return ""
}

func claim(claims map[string]*string, key string) string {
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(safeString(claims[key]))
}

func isObjectID(raw string) bool {
	if len(raw) != 36 {
		return false
	}
	for i, r := range raw {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
				return false
			}
		}
	}
	return true
}

func clientIP(event *armmonitor.EventData) string {
	if event.HTTPRequest == nil {
		return ""
	}
	return strings.TrimSpace(safeString(event.HTTPRequest.ClientIPAddress))
}

func requestReadOnly(event *armmonitor.EventData) bool {
	if event.HTTPRequest == nil || event.HTTPRequest.Method == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(*event.HTTPRequest.Method), "GET")
}

func addAuditEvent(batch *graph.Batch, nodeID string, event graph.AuditEvent, counts map[string]int) {
	if nodeID == "" || counts[nodeID] >= auditMaxPerNode {
		return
	}
	for i := range batch.Nodes {
		if batch.Nodes[i].ID != nodeID {
			continue
		}
		if batch.Nodes[i].Properties == nil {
			batch.Nodes[i].Properties = map[string]any{}
		}
		events := append(graph.AuditEventsFrom(batch.Nodes[i].Properties), event)
		graph.SetAuditEvents(batch.Nodes[i].Properties, events)
		counts[nodeID]++
		return
	}
}

func sortAuditsNewestFirst(events []matchedAudit) {
	for i := 1; i < len(events); i++ {
		item := events[i]
		j := i
		for j > 0 && events[j-1].when.Before(item.when) {
			events[j] = events[j-1]
			j--
		}
		events[j] = item
	}
}

func exposedNodeIDs(batch *graph.Batch) map[string]bool {
	exposed := map[string]bool{}
	reachable := map[string]bool{}
	for _, edge := range batch.Edges {
		if edge.Type == graph.EdgeReachable && edge.SourceID == graph.InternetNodeID {
			reachable[edge.TargetID] = true
			exposed[edge.TargetID] = true
		}
	}
	assumed := map[string]bool{}
	for _, edge := range batch.Edges {
		if edge.Type == graph.EdgeAssumes && reachable[edge.SourceID] {
			assumed[edge.TargetID] = true
			exposed[edge.TargetID] = true
		}
	}
	for _, edge := range batch.Edges {
		if edge.Type != graph.EdgeCanAccess {
			continue
		}
		if reachable[edge.SourceID] || assumed[edge.SourceID] {
			exposed[edge.TargetID] = true
		}
	}
	for _, edge := range batch.Edges {
		if edge.Type == graph.EdgeAffects && reachable[edge.SourceID] {
			exposed[edge.TargetID] = true
		}
	}
	public := map[string]bool{}
	for _, node := range batch.Nodes {
		if node.Type != graph.NodeDatastore || !boolProp(node.Properties, "public_access") {
			continue
		}
		public[node.ID] = true
		exposed[node.ID] = true
	}
	for _, edge := range batch.Edges {
		if edge.Type == graph.EdgeCanAccess && public[edge.TargetID] {
			exposed[edge.SourceID] = true
		}
	}
	return exposed
}

func boolProp(props map[string]any, key string) bool {
	if props == nil {
		return false
	}
	value, ok := props[key].(bool)
	return ok && value
}

type azureAuditIndex struct {
	byKey      map[string]string
	isIdentity map[string]bool
}

func buildAzureAuditIndex(batch *graph.Batch) *azureAuditIndex {
	index := &azureAuditIndex{
		byKey:      map[string]string{},
		isIdentity: map[string]bool{},
	}
	for _, node := range batch.Nodes {
		if node.Type == graph.NodeIdentity && node.Name != "" {
			index.isIdentity[node.ID] = true
			index.add("principal:"+strings.ToLower(node.Name), node.ID)
		}
		if rid, ok := stringProp(node.Properties, "resource_id"); ok {
			index.add("id:"+strings.ToLower(rid), node.ID)
		}
	}
	return index
}

func (index *azureAuditIndex) add(key, id string) {
	if key == "" || id == "" {
		return
	}
	if prev, ok := index.byKey[key]; ok && prev != id {
		index.byKey[key] = ""
		return
	}
	index.byKey[key] = id
}

func (index *azureAuditIndex) get(key string) (string, bool) {
	id, ok := index.byKey[key]
	return id, ok && id != ""
}

func (index *azureAuditIndex) principal(event *armmonitor.EventData) (string, bool) {
	raw := objectID(event)
	if raw == "" {
		return "", false
	}
	id, ok := index.get("principal:" + strings.ToLower(raw))
	if !ok || !index.isIdentity[id] {
		return "", false
	}
	return id, true
}

func (index *azureAuditIndex) resource(event *armmonitor.EventData, principalID string, exposed map[string]bool) (string, string, bool) {
	var candidates []string
	if rid := strings.TrimSpace(safeString(event.ResourceID)); rid != "" {
		candidates = append(candidates, rid)
	}
	if event.Authorization != nil {
		if scope := strings.TrimSpace(safeString(event.Authorization.Scope)); scope != "" {
			candidates = append(candidates, scope)
		}
	}
	var fallbackRaw, fallbackID string
	for _, raw := range candidates {
		id, ok := index.resolve(raw)
		if !ok || !exposed[id] {
			continue
		}
		if id != principalID {
			return raw, id, true
		}
		if fallbackID == "" {
			fallbackRaw, fallbackID = raw, id
		}
	}
	if fallbackID != "" && exposed[principalID] {
		return fallbackRaw, fallbackID, true
	}
	if exposed[principalID] {
		raw := strings.TrimSpace(safeString(event.Caller))
		if raw == "" {
			raw = objectID(event)
		}
		if raw == "" {
			return "", "", false
		}
		return raw, principalID, true
	}
	return "", "", false
}

func (index *azureAuditIndex) resolve(raw string) (string, bool) {
	current := strings.TrimRight(strings.TrimSpace(raw), "/")
	if current == "" || current == "*" {
		return "", false
	}
	for {
		if id, ok := index.get("id:" + strings.ToLower(current)); ok {
			return id, true
		}
		if subscriptionRoot(current) {
			return "", false
		}
		i := strings.LastIndex(current, "/")
		if i <= 0 {
			return "", false
		}
		current = current[:i]
	}
}

func subscriptionRoot(raw string) bool {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimRight(raw, "/")), "/subscriptions/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

func stringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	value, ok := props[key].(string)
	return value, ok && value != ""
}
