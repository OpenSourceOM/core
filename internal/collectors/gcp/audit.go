// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
	loggingapi "google.golang.org/api/logging/v2"
)

const (
	auditLookupWindow = 24 * time.Hour
	auditPageSize     = 50
	auditMaxPages     = 4
	auditMaxPerNode   = 5
)

// auditMethodSuffixes are Admin Activity methods that show a principal
// changing an identity, datastore, workload, or network control.
// Data Access logs, including object reads, are a different log and are not listed.
var auditMethodSuffixes = []string{
	"compute.instances.insert",
	"compute.instances.delete",
	"compute.instances.addaccessconfig",
	"compute.instances.deleteaccessconfig",
	"compute.instances.setserviceaccount",
	"compute.firewalls.insert",
	"compute.firewalls.patch",
	"compute.firewalls.update",
	"compute.firewalls.delete",
	"storage.buckets.create",
	"storage.buckets.delete",
	"storage.buckets.update",
	"storage.setiampermissions",
	"google.iam.admin.v1.createserviceaccount",
	"google.iam.admin.v1.deleteserviceaccount",
	"google.iam.admin.v1.createserviceaccountkey",
	"google.iam.admin.v1.deleteserviceaccountkey",
	"cloudsql.instances.insert",
	"cloudsql.instances.update",
	"cloudsql.instances.patch",
	"cloudsql.instances.delete",
}

// auditEntry is one Admin Activity log entry, detached from the SDK type.
type auditEntry struct {
	InsertID     string
	Timestamp    string
	ProtoPayload []byte
	LogName      string
}

type auditPayload struct {
	ServiceName        string `json:"serviceName"`
	MethodName         string `json:"methodName"`
	ResourceName       string `json:"resourceName"`
	AuthenticationInfo struct {
		PrincipalEmail   string `json:"principalEmail"`
		PrincipalSubject string `json:"principalSubject"`
	} `json:"authenticationInfo"`
	RequestMetadata struct {
		CallerIP string `json:"callerIp"`
	} `json:"requestMetadata"`
	AuthorizationInfo []struct {
		Resource string `json:"resource"`
	} `json:"authorizationInfo"`
}

// auditPager is one page of Admin Activity log entries.
type auditPager interface {
	More() bool
	NextPage(context.Context) ([]auditEntry, error)
}

// loggingAPI opens a paged Admin Activity query. A nil client omits events.
type loggingAPI interface {
	ListPager(since time.Time) (auditPager, error)
}

type gcpLogging struct {
	service   *loggingapi.Service
	projectID string
}

func (c *Collector) auditLogs(ctx context.Context) loggingAPI {
	if c.ProjectID == "" {
		return nil
	}
	service, err := loggingapi.NewService(ctx)
	if err != nil {
		return nil
	}
	return &gcpLogging{service: service, projectID: c.ProjectID}
}

func (g *gcpLogging) ListPager(since time.Time) (auditPager, error) {
	if g == nil || g.service == nil || g.service.Entries == nil || g.projectID == "" {
		return nil, nil
	}
	return &loggingPager{service: g.service, projectID: g.projectID, since: since.UTC()}, nil
}

type loggingPager struct {
	service   *loggingapi.Service
	projectID string
	since     time.Time
	token     string
	done      bool
}

func (p *loggingPager) More() bool {
	return p != nil && !p.done
}

func (p *loggingPager) NextPage(ctx context.Context) ([]auditEntry, error) {
	resp, err := p.service.Entries.List(&loggingapi.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + p.projectID},
		Filter:        auditFilter(p.projectID, p.since),
		OrderBy:       "timestamp desc",
		PageSize:      auditPageSize,
		PageToken:     p.token,
	}).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.NextPageToken == "" {
		p.done = true
	} else {
		p.token = resp.NextPageToken
	}
	if resp == nil {
		return nil, nil
	}
	entries := make([]auditEntry, 0, len(resp.Entries))
	for _, entry := range resp.Entries {
		if entry == nil {
			continue
		}
		entries = append(entries, auditEntry{
			InsertID:     entry.InsertId,
			Timestamp:    entry.Timestamp,
			ProtoPayload: append([]byte(nil), entry.ProtoPayload...),
			LogName:      entry.LogName,
		})
	}
	return entries, nil
}

func auditFilter(project string, since time.Time) string {
	return `logName="projects/` + project + `/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp>="` + since.UTC().Format(time.RFC3339) + `"`
}

type matchedAudit struct {
	event graph.AuditEvent
	when  time.Time
}

// attachAuditEvents stores recent Admin Activity events on the identity and
// resource nodes they name. A lookup error omits the property. Events are
// kept only when the resource sits on an exposed path in this batch:
// internet-reachable, assumed by such a workload, able to reach that
// workload's data, or a public datastore and the identities that can access it.
func (c *Collector) attachAuditEvents(ctx context.Context, client loggingAPI, batch *graph.Batch) {
	if client == nil || batch == nil || c.ProjectID == "" {
		return
	}
	exposed := exposedNodeIDs(batch)
	if len(exposed) == 0 {
		return
	}
	until := time.Now().UTC()
	pager, err := client.ListPager(until.Add(-auditLookupWindow))
	if err != nil || pager == nil {
		return
	}
	events, _ := listAuditEntries(ctx, pager)
	index := buildGCPAuditIndex(batch)
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

func listAuditEntries(ctx context.Context, pager auditPager) ([]auditEntry, error) {
	if pager == nil {
		return nil, nil
	}
	var events []auditEntry
	for page := 0; page < auditMaxPages && pager.More(); page++ {
		batch, err := pager.NextPage(ctx)
		if err != nil {
			return events, err
		}
		events = append(events, batch...)
	}
	return events, nil
}

func (c *Collector) matchAuditEvent(entry auditEntry, index *gcpAuditIndex, exposed map[string]bool) (matchedAudit, bool) {
	if !c.logInProject(entry.LogName) {
		return matchedAudit{}, false
	}
	payload, ok := parseAuditPayload(entry.ProtoPayload)
	if !ok || !auditMethodAllowed(payload.ServiceName, payload.MethodName) {
		return matchedAudit{}, false
	}
	id := strings.TrimSpace(entry.InsertID)
	if id == "" {
		return matchedAudit{}, false
	}
	when, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.Timestamp))
	if err != nil {
		return matchedAudit{}, false
	}
	principal, principalID, ok := index.principal(payload)
	if !ok {
		return matchedAudit{}, false
	}
	resourceRaw, resourceID, ok := index.resource(payload, principalID, exposed, c.ProjectID)
	if !ok {
		return matchedAudit{}, false
	}
	return matchedAudit{
		when: when.UTC(),
		event: graph.AuditEvent{
			ID:              id,
			Name:            strings.TrimSpace(payload.MethodName),
			Time:            when.UTC().Format(time.RFC3339),
			Principal:       principal,
			Resource:        resourceRaw,
			PrincipalNodeID: principalID,
			ResourceNodeID:  resourceID,
			SourceIP:        strings.TrimSpace(payload.RequestMetadata.CallerIP),
			ReadOnly:        false,
		},
	}, true
}

func (c *Collector) logInProject(logName string) bool {
	project := strings.ToLower(strings.TrimSpace(c.ProjectID))
	if project == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(logName))
	prefix := "projects/" + project + "/logs/"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := strings.TrimPrefix(name, prefix)
	return rest == "cloudaudit.googleapis.com%2factivity" || rest == "cloudaudit.googleapis.com/activity"
}

func parseAuditPayload(raw []byte) (auditPayload, bool) {
	if len(raw) == 0 {
		return auditPayload{}, false
	}
	var payload auditPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return auditPayload{}, false
	}
	if strings.TrimSpace(payload.MethodName) == "" {
		return auditPayload{}, false
	}
	return payload, true
}

func auditMethodAllowed(service, method string) bool {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return false
	}
	for _, suffix := range auditMethodSuffixes {
		if method == suffix || strings.HasSuffix(method, "."+suffix) {
			return true
		}
	}
	if method == "setiampolicy" || strings.HasSuffix(method, ".setiampolicy") {
		switch strings.ToLower(strings.TrimSpace(service)) {
		case "cloudresourcemanager.googleapis.com", "storage.googleapis.com", "iam.googleapis.com":
			return true
		}
	}
	return false
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

type gcpAuditIndex struct {
	byKey      map[string]string
	isIdentity map[string]bool
}

func buildGCPAuditIndex(batch *graph.Batch) *gcpAuditIndex {
	index := &gcpAuditIndex{
		byKey:      map[string]string{},
		isIdentity: map[string]bool{},
	}
	for _, node := range batch.Nodes {
		if node.Type == graph.NodeIdentity {
			index.isIdentity[node.ID] = true
			if email, ok := stringProp(node.Properties, "email"); ok {
				index.add("principal:"+strings.ToLower(email), node.ID)
			}
			if node.Name != "" {
				index.add("principal:"+strings.ToLower(node.Name), node.ID)
			}
		}
		if rid, ok := stringProp(node.Properties, "resource_id"); ok {
			index.add("id:"+canonicalResource(rid), node.ID)
		}
		service, _ := stringProp(node.Properties, "service")
		if node.Type == graph.NodeDatastore && (service == "" || service == "gcs") && node.Name != "" {
			index.add("bucket:"+strings.ToLower(node.Name), node.ID)
		}
		if service == "cloudsql" && node.Name != "" {
			index.add("sql:"+strings.ToLower(node.Name), node.ID)
		}
	}
	return index
}

func (index *gcpAuditIndex) add(key, id string) {
	if key == "" || id == "" {
		return
	}
	if prev, ok := index.byKey[key]; ok && prev != id {
		index.byKey[key] = ""
		return
	}
	index.byKey[key] = id
}

func (index *gcpAuditIndex) get(key string) (string, bool) {
	id, ok := index.byKey[key]
	return id, ok && id != ""
}

func (index *gcpAuditIndex) principal(payload auditPayload) (string, string, bool) {
	email := strings.ToLower(strings.TrimSpace(payload.AuthenticationInfo.PrincipalEmail))
	if email == "" {
		email = subjectEmail(payload.AuthenticationInfo.PrincipalSubject)
	}
	if email == "" {
		return "", "", false
	}
	id, ok := index.get("principal:" + email)
	if !ok || !index.isIdentity[id] {
		return "", "", false
	}
	return email, id, true
}

func (index *gcpAuditIndex) resource(payload auditPayload, principalID string, exposed map[string]bool, projectID string) (string, string, bool) {
	var candidates []string
	if name := strings.TrimSpace(payload.ResourceName); name != "" {
		candidates = append(candidates, name)
	}
	for _, auth := range payload.AuthorizationInfo {
		if name := strings.TrimSpace(auth.Resource); name != "" {
			candidates = append(candidates, name)
		}
	}
	var fallbackRaw, fallbackID string
	foreign := false
	for _, raw := range candidates {
		if !resourceInProject(raw, projectID) {
			foreign = true
			continue
		}
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
	if foreign && fallbackID == "" {
		return "", "", false
	}
	if fallbackID != "" && exposed[principalID] {
		return fallbackRaw, fallbackID, true
	}
	if exposed[principalID] && !foreign {
		raw := strings.TrimSpace(payload.AuthenticationInfo.PrincipalEmail)
		if raw == "" {
			raw = subjectEmail(payload.AuthenticationInfo.PrincipalSubject)
		}
		if raw == "" {
			return "", "", false
		}
		return raw, principalID, true
	}
	return "", "", false
}

func (index *gcpAuditIndex) resolve(raw string) (string, bool) {
	original := canonicalResource(raw)
	if original == "" || original == "*" {
		return "", false
	}
	current := original
	for {
		if id, ok := index.get("id:" + current); ok {
			return id, true
		}
		if projectRoot(current) {
			break
		}
		i := strings.LastIndex(current, "/")
		if i <= 0 {
			break
		}
		current = current[:i]
	}
	if bucket, ok := bucketName(original); ok {
		if id, ok := index.get("bucket:" + bucket); ok {
			return id, true
		}
	}
	if email, ok := serviceAccountEmailFromResource(original); ok {
		if id, ok := index.get("principal:" + email); ok && index.isIdentity[id] {
			return id, true
		}
	}
	if name, ok := cloudSQLName(original); ok {
		if id, ok := index.get("sql:" + name); ok {
			return id, true
		}
	}
	return "", false
}

func subjectEmail(subject string) string {
	subject = strings.TrimSpace(subject)
	const prefix = "serviceAccount:"
	if len(subject) > len(prefix) && strings.EqualFold(subject[:len(prefix)], prefix) {
		return strings.ToLower(strings.TrimSpace(subject[len(prefix):]))
	}
	if strings.Contains(subject, "@") {
		return strings.ToLower(subject)
	}
	return ""
}

func canonicalResource(raw string) string {
	raw = strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return ""
		}
		raw = rest[slash+1:]
	}
	for _, prefix := range []string{"compute/v1/", "compute/beta/", "compute/alpha/"} {
		raw = strings.TrimPrefix(raw, prefix)
	}
	return raw
}

func resourceInProject(raw, projectID string) bool {
	canonical := canonicalResource(raw)
	if canonical == "" || canonical == "*" {
		return false
	}
	project := strings.ToLower(strings.TrimSpace(projectID))
	if project == "" || !strings.HasPrefix(canonical, "projects/") {
		return project != ""
	}
	rest := strings.TrimPrefix(canonical, "projects/")
	proj := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		proj = rest[:i]
	}
	return proj == project || proj == "_"
}

func projectRoot(raw string) bool {
	rest, ok := strings.CutPrefix(raw, "projects/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

func bucketName(raw string) (string, bool) {
	const marker = "/buckets/"
	i := strings.Index(raw, marker)
	if i < 0 {
		return "", false
	}
	name := raw[i+len(marker):]
	if slash := strings.Index(name, "/"); slash >= 0 {
		name = name[:slash]
	}
	if name == "" || name == "_" {
		return "", false
	}
	return name, true
}

func serviceAccountEmailFromResource(raw string) (string, bool) {
	const marker = "/serviceaccounts/"
	i := strings.Index(raw, marker)
	if i < 0 {
		return "", false
	}
	email := raw[i+len(marker):]
	if slash := strings.Index(email, "/"); slash >= 0 {
		email = email[:slash]
	}
	if email == "" || !strings.Contains(email, "@") {
		return "", false
	}
	return email, true
}

func cloudSQLName(raw string) (string, bool) {
	if strings.Contains(raw, "/zones/") || strings.Contains(raw, "/regions/") {
		return "", false
	}
	const marker = "/instances/"
	i := strings.Index(raw, marker)
	if i < 0 || !strings.Contains(raw[:i], "projects/") {
		return "", false
	}
	name := raw[i+len(marker):]
	if slash := strings.Index(name, "/"); slash >= 0 {
		name = name[:slash]
	}
	if name == "" {
		return "", false
	}
	return name, true
}

func stringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	value, ok := props[key].(string)
	return value, ok && value != ""
}
