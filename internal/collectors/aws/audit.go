// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

const (
	auditLookupWindow = 24 * time.Hour
	auditPageSize     = 50
	auditMaxPages     = 4
	auditMaxPerNode   = 5
)

// auditEventNames are management events that show a principal using or
// changing an identity, datastore, workload, or network control.
// LookupEvents does not return S3 object data events such as GetObject.
var auditEventNames = map[string]struct{}{
	"AssumeRole":                    {},
	"AssumeRoleWithSAML":            {},
	"AssumeRoleWithWebIdentity":     {},
	"ConsoleLogin":                  {},
	"PutBucketPolicy":               {},
	"PutBucketAcl":                  {},
	"PutPublicAccessBlock":          {},
	"DeletePublicAccessBlock":       {},
	"AuthorizeSecurityGroupIngress": {},
	"AuthorizeSecurityGroupEgress":  {},
	"RevokeSecurityGroupIngress":    {},
	"RevokeSecurityGroupEgress":     {},
	"CreateAccessKey":               {},
	"AttachRolePolicy":              {},
	"AttachUserPolicy":              {},
	"PutRolePolicy":                 {},
	"PutUserPolicy":                 {},
	"RunInstances":                  {},
	"ModifyDBInstance":              {},
}

// cloudTrailAPI is the LookupEvents call the collector pages.
type cloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

var _ cloudTrailAPI = (*cloudtrail.Client)(nil)

type trailPayload struct {
	UserIdentity struct {
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	SourceIPAddress   string         `json:"sourceIPAddress"`
	RequestParameters map[string]any `json:"requestParameters"`
	Resources         []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

type matchedAudit struct {
	event graph.AuditEvent
	when  time.Time
}

// attachAuditEvents stores recent CloudTrail management events on the
// identity and resource nodes they name. A lookup error omits the property.
// Events are kept only when the resource sits on an exposed path in this batch:
// internet-reachable, assumed by such a workload, able to reach that workload's
// data, or a public datastore and the identities that can access it.
func (c *Collector) attachAuditEvents(ctx context.Context, client cloudTrailAPI, batch *graph.Batch) {
	if client == nil || batch == nil || c.AccountID == "" {
		return
	}
	exposed := exposedNodeIDs(batch)
	if len(exposed) == 0 {
		return
	}
	index := buildAuditIndex(batch)
	var matched []matchedAudit
	seen := map[string]bool{}
	for _, region := range c.auditRegions() {
		events, _ := c.lookupRegion(ctx, client, region)
		for _, event := range events {
			item, ok := c.matchAuditEvent(event, index, exposed)
			if !ok || seen[item.event.ID] {
				continue
			}
			seen[item.event.ID] = true
			matched = append(matched, item)
		}
	}
	if len(matched) == 0 {
		return
	}
	sortAuditsNewestFirst(matched)
	counts := map[string]int{}
	for _, item := range matched {
		c.addAuditEvent(batch, item.event.PrincipalNodeID, item.event, counts)
		if item.event.ResourceNodeID != item.event.PrincipalNodeID {
			c.addAuditEvent(batch, item.event.ResourceNodeID, item.event, counts)
		}
	}
}

func (c *Collector) auditRegions() []string {
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	regions := []string{region}
	if region != "us-east-1" {
		regions = append(regions, "us-east-1")
	}
	return regions
}

func (c *Collector) lookupRegion(ctx context.Context, client cloudTrailAPI, region string) ([]trailtypes.Event, error) {
	start := time.Now().Add(-auditLookupWindow)
	var token *string
	var events []trailtypes.Event
	for page := 0; page < auditMaxPages; page++ {
		out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime:  &start,
			MaxResults: aws.Int32(auditPageSize),
			NextToken:  token,
		}, func(o *cloudtrail.Options) {
			o.Region = region
		})
		if err != nil {
			return events, err
		}
		if out == nil {
			return events, nil
		}
		events = append(events, out.Events...)
		if out.NextToken == nil || *out.NextToken == "" {
			return events, nil
		}
		token = out.NextToken
	}
	return events, nil
}

func (c *Collector) matchAuditEvent(event trailtypes.Event, index *auditIndex, exposed map[string]bool) (matchedAudit, bool) {
	name := aws.ToString(event.EventName)
	if _, ok := auditEventNames[name]; !ok {
		return matchedAudit{}, false
	}
	id := aws.ToString(event.EventId)
	if id == "" || event.EventTime == nil {
		return matchedAudit{}, false
	}
	payload := parseTrailPayload(aws.ToString(event.CloudTrailEvent))
	if payload.UserIdentity.AccountID != "" && payload.UserIdentity.AccountID != c.AccountID {
		return matchedAudit{}, false
	}
	principalARN, principalID, ok := index.principal(payload, c.AccountID)
	if !ok {
		return matchedAudit{}, false
	}
	resourceRaw, resourceID, ok := index.resource(payload, event.Resources, principalID, exposed, c.AccountID)
	if !ok {
		return matchedAudit{}, false
	}
	return matchedAudit{
		when: event.EventTime.UTC(),
		event: graph.AuditEvent{
			ID:              id,
			Name:            name,
			Time:            event.EventTime.UTC().Format(time.RFC3339),
			Principal:       principalARN,
			Resource:        resourceRaw,
			PrincipalNodeID: principalID,
			ResourceNodeID:  resourceID,
			SourceIP:        payload.SourceIPAddress,
			ReadOnly:        strings.EqualFold(aws.ToString(event.ReadOnly), "true"),
		},
	}, true
}

func parseTrailPayload(raw string) trailPayload {
	var payload trailPayload
	if raw == "" {
		return payload
	}
	_ = json.Unmarshal([]byte(raw), &payload)
	return payload
}

func (c *Collector) addAuditEvent(batch *graph.Batch, nodeID string, event graph.AuditEvent, counts map[string]int) {
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

type auditIndex struct {
	byKey      map[string]string
	isIdentity map[string]bool
}

func buildAuditIndex(batch *graph.Batch) *auditIndex {
	index := &auditIndex{
		byKey:      map[string]string{},
		isIdentity: map[string]bool{},
	}
	for _, node := range batch.Nodes {
		if node.Type == graph.NodeIdentity {
			index.isIdentity[node.ID] = true
			if kind, ok := stringProp(node.Properties, "principal_type"); ok && node.Name != "" {
				index.add(kind+":"+node.Name, node.ID)
			}
		}
		if arn, _ := stringProp(node.Properties, "arn"); arn != "" {
			index.add("arn:"+arn, node.ID)
		}
		if rid, _ := stringProp(node.Properties, "resource_id"); rid != "" {
			index.add("id:"+rid, node.ID)
			if strings.HasPrefix(rid, "arn:") {
				index.add("arn:"+rid, node.ID)
			}
		}
		if service, _ := stringProp(node.Properties, "service"); service == "s3" && node.Name != "" {
			index.add("s3:"+node.Name, node.ID)
			index.add("id:"+node.Name, node.ID)
		}
	}
	return index
}

func (index *auditIndex) add(key, id string) {
	if key == "" || id == "" {
		return
	}
	if prev, ok := index.byKey[key]; ok && prev != id {
		index.byKey[key] = ""
		return
	}
	index.byKey[key] = id
}

func (index *auditIndex) get(key string) (string, bool) {
	id, ok := index.byKey[key]
	return id, ok && id != ""
}

func (index *auditIndex) principal(payload trailPayload, accountID string) (string, string, bool) {
	candidates := []string{
		payload.UserIdentity.ARN,
		payload.UserIdentity.SessionContext.SessionIssuer.ARN,
	}
	if role, ok := iamRoleARN(payload.UserIdentity.ARN); ok {
		candidates = append(candidates, role)
	}
	for _, raw := range candidates {
		if raw == "" || !arnInAccount(raw, accountID) {
			continue
		}
		id, ok := index.get("arn:" + raw)
		if ok && index.isIdentity[id] {
			return raw, id, true
		}
		if role, ok := iamRoleARN(raw); ok && role != raw && arnInAccount(role, accountID) {
			id, ok = index.get("arn:" + role)
			if ok && index.isIdentity[id] {
				return role, id, true
			}
		}
	}
	return "", "", false
}

func (index *auditIndex) resource(payload trailPayload, listed []trailtypes.Resource, principalID string, exposed map[string]bool, accountID string) (string, string, bool) {
	var candidates []string
	for _, resource := range listed {
		if name := aws.ToString(resource.ResourceName); name != "" {
			candidates = append(candidates, name)
		}
	}
	for _, resource := range payload.Resources {
		if resource.ARN != "" {
			candidates = append(candidates, resource.ARN)
		}
	}
	for _, key := range []string{"roleArn", "bucketName", "userName", "groupId", "instanceId"} {
		if value, ok := payload.RequestParameters[key].(string); ok && value != "" {
			candidates = append(candidates, value)
		}
	}
	var fallbackRaw, fallbackID string
	for _, raw := range candidates {
		id, ok := index.resolve(raw, accountID)
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
		for _, raw := range []string{payload.UserIdentity.ARN, payload.UserIdentity.SessionContext.SessionIssuer.ARN} {
			if raw == "" {
				continue
			}
			return raw, principalID, true
		}
	}
	return "", "", false
}

func (index *auditIndex) resolve(raw, accountID string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" {
		return "", false
	}
	if !arnInAccount(raw, accountID) {
		return "", false
	}
	if id, ok := index.get("arn:" + raw); ok {
		return id, true
	}
	if id, ok := index.get("id:" + raw); ok {
		return id, true
	}
	if bucket, ok := s3Bucket(raw); ok {
		if id, ok := index.get("s3:" + bucket); ok {
			return id, true
		}
	}
	if id, ok := ec2ResourceID(raw); ok {
		if node, ok := index.get("id:" + id); ok {
			return node, true
		}
	}
	if role, ok := iamRoleARN(raw); ok {
		if node, ok := index.get("arn:" + role); ok {
			return node, true
		}
	}
	if !strings.Contains(raw, ":") {
		if id, ok := index.bareIdentity(raw); ok {
			return id, true
		}
	}
	return "", false
}

func (index *auditIndex) bareIdentity(raw string) (string, bool) {
	user, userOK := index.get("user:" + raw)
	role, roleOK := index.get("role:" + raw)
	switch {
	case userOK && roleOK:
		return "", false
	case userOK:
		return user, true
	case roleOK:
		return role, true
	default:
		return "", false
	}
}

func stringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	value, ok := props[key].(string)
	return value, ok && value != ""
}

func arnInAccount(raw, accountID string) bool {
	if !strings.HasPrefix(raw, "arn:") {
		return true
	}
	account := arnField(raw, 4)
	return account == "" || account == accountID
}

func arnField(raw string, index int) string {
	parts := strings.Split(raw, ":")
	if len(parts) <= index || parts[0] != "arn" {
		return ""
	}
	return parts[index]
}

func s3Bucket(raw string) (string, bool) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "s3" {
		return "", false
	}
	bucket := parts[5]
	if i := strings.Index(bucket, "/"); i >= 0 {
		bucket = bucket[:i]
	}
	if bucket == "" {
		return "", false
	}
	return bucket, true
}

func ec2ResourceID(raw string) (string, bool) {
	if strings.HasPrefix(raw, "i-") || strings.HasPrefix(raw, "sg-") {
		return raw, true
	}
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "ec2" {
		return "", false
	}
	switch {
	case strings.HasPrefix(parts[5], "instance/"):
		return strings.TrimPrefix(parts[5], "instance/"), true
	case strings.HasPrefix(parts[5], "security-group/"):
		return strings.TrimPrefix(parts[5], "security-group/"), true
	default:
		return "", false
	}
}

func iamRoleARN(raw string) (string, bool) {
	if strings.Contains(raw, ":role/") && strings.HasPrefix(raw, "arn:") {
		return raw, true
	}
	const marker = ":assumed-role/"
	i := strings.Index(raw, marker)
	if i < 0 || !strings.HasPrefix(raw, "arn:") {
		return "", false
	}
	rest := raw[i+len(marker):]
	name := rest
	if slash := strings.Index(rest, "/"); slash >= 0 {
		name = rest[:slash]
	}
	if name == "" {
		return "", false
	}
	partition := arnField(raw, 1)
	account := arnField(raw, 4)
	if partition == "" || account == "" {
		return "", false
	}
	return "arn:" + partition + ":iam::" + account + ":role/" + name, true
}
