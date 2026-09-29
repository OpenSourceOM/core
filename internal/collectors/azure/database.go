// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

// azureSQLAPIVersion is the stable SQL server API that returns public network
// access, firewall ranges, and virtual network rules.
const azureSQLAPIVersion = "2021-11-01"

// azureWorkloadNet is a VM and the addresses used to decide whether it can
// reach an Azure SQL server. Default outbound SNAT, private endpoints, and
// peering are not treated as a path.
type azureWorkloadNet struct {
	WorkloadID string
	PublicIPs  []string
	SubnetIDs  []string
}

type sqlFirewall struct {
	start string
	end   string
}

type sqlServer struct {
	name           string
	resourceID     string
	location       string
	publicEndpoint bool
	publicAccess   bool
	rules          []sqlFirewall
	subnets        []string
}

// collectSQL adds one Datastore per logical server. Databases on a server
// share its firewall, so they are not separate nodes. CAN_ACCESS follows a
// virtual-network rule for the VM's subnet, or a firewall range that contains
// the VM's public IP. Same-subscription membership is not enough.
func (c *Collector) collectSQL(ctx context.Context, cred azcore.TokenCredential, batch *graph.Batch, workloads []azureWorkloadNet) error {
	client, err := armresources.NewClient(c.SubscriptionID, cred, nil)
	if err != nil {
		return err
	}
	servers, err := readSQLResources(ctx, client, "Microsoft.Sql/servers")
	if err != nil {
		return err
	}
	sqlClient, err := arm.NewClient("github.com/OpenSourceOM/core/internal/collectors/azure", "v0.0.0", cred, nil)
	if err != nil {
		return err
	}
	var firewalls []*armresources.GenericResourceExpanded
	var vnetRules []*armresources.GenericResourceExpanded
	for _, server := range servers {
		if server == nil || server.ID == nil || *server.ID == "" {
			continue
		}
		rules, err := listSQLChildren(ctx, sqlClient, *server.ID, "firewallRules")
		if err != nil {
			return err
		}
		firewalls = append(firewalls, rules...)
		nets, err := listSQLChildren(ctx, sqlClient, *server.ID, "virtualNetworkRules")
		if err != nil {
			return err
		}
		vnetRules = append(vnetRules, nets...)
	}
	model := assembleSQLServers(servers, firewalls, vnetRules)
	c.addSQLNodes(batch, model)
	c.linkAzureSQL(batch, model, workloads)
	return nil
}

func readSQLResources(ctx context.Context, client *armresources.Client, resourceType string) ([]*armresources.GenericResourceExpanded, error) {
	filter := fmt.Sprintf("resourceType eq '%s'", resourceType)
	var listed []*armresources.GenericResourceExpanded
	pager := client.NewListPager(&armresources.ClientListOptions{Filter: &filter})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", resourceType, err)
		}
		listed = append(listed, page.Value...)
	}
	var full []*armresources.GenericResourceExpanded
	for _, item := range listed {
		if item == nil || item.ID == nil || *item.ID == "" {
			continue
		}
		if sqlPropertiesComplete(resourceType, item.Properties) {
			full = append(full, item)
			continue
		}
		got, err := client.GetByID(ctx, *item.ID, azureSQLAPIVersion, nil)
		if err != nil {
			if azureNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get %s: %w", *item.ID, err)
		}
		full = append(full, expandedFromGet(item, got.GenericResource))
	}
	return full, nil
}

func listSQLChildren(ctx context.Context, client *arm.Client, serverID, child string) ([]*armresources.GenericResourceExpanded, error) {
	next := strings.TrimRight(client.Endpoint(), "/") + "/" + strings.TrimLeft(serverID, "/") + "/" + child + "?api-version=" + azureSQLAPIVersion
	var out []*armresources.GenericResourceExpanded
	for next != "" {
		req, err := runtime.NewRequest(ctx, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		req.Raw().Header.Set("Accept", "application/json")
		resp, err := client.Pipeline().Do(req)
		if err != nil {
			return nil, fmt.Errorf("list %s for %s: %w", child, serverID, err)
		}
		if !runtime.HasStatusCode(resp, http.StatusOK) {
			err = runtime.NewResponseError(resp)
			resp.Body.Close()
			if azureNotFound(err) {
				return out, nil
			}
			return nil, fmt.Errorf("list %s for %s: %w", child, serverID, err)
		}
		var page struct {
			Value []struct {
				ID         string         `json:"id"`
				Name       string         `json:"name"`
				Type       string         `json:"type"`
				Properties map[string]any `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		err = runtime.UnmarshalAsJSON(resp, &page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("list %s for %s: %w", child, serverID, err)
		}
		for _, item := range page.Value {
			id, name, resourceType := item.ID, item.Name, item.Type
			props := map[string]any{}
			for key, value := range item.Properties {
				props[key] = value
			}
			out = append(out, &armresources.GenericResourceExpanded{
				ID:         &id,
				Name:       &name,
				Type:       &resourceType,
				Properties: props,
			})
		}
		next = page.NextLink
	}
	return out, nil
}

func sqlPropertiesComplete(resourceType string, props any) bool {
	m := propMap(props)
	switch resourceType {
	case "Microsoft.Sql/servers":
		_, ok := m["publicNetworkAccess"]
		return ok
	case "Microsoft.Sql/servers/firewallRules":
		return propString(m, "startIpAddress") != "" && propString(m, "endIpAddress") != ""
	case "Microsoft.Sql/servers/virtualNetworkRules":
		return propString(m, "virtualNetworkSubnetId") != ""
	default:
		return false
	}
}

func expandedFromGet(listed *armresources.GenericResourceExpanded, got armresources.GenericResource) *armresources.GenericResourceExpanded {
	out := *listed
	if got.ID != nil {
		out.ID = got.ID
	}
	if got.Name != nil {
		out.Name = got.Name
	}
	if got.Location != nil {
		out.Location = got.Location
	}
	if got.Properties != nil {
		out.Properties = got.Properties
	}
	return &out
}

func assembleSQLServers(servers, firewalls, vnetRules []*armresources.GenericResourceExpanded) []sqlServer {
	byName := map[string]*sqlServer{}
	var ordered []string
	for _, item := range servers {
		if item == nil {
			continue
		}
		name := safeString(item.Name)
		if name == "" {
			parsed, ok := sqlServerName(safeString(item.ID))
			if !ok {
				continue
			}
			name = parsed
		}
		key := strings.ToLower(name)
		if _, ok := byName[key]; ok {
			continue
		}
		access := propString(propMap(item.Properties), "publicNetworkAccess")
		byName[key] = &sqlServer{
			name:           name,
			resourceID:     safeString(item.ID),
			location:       safeString(item.Location),
			publicEndpoint: !strings.EqualFold(strings.TrimSpace(access), "Disabled"),
		}
		ordered = append(ordered, key)
	}
	for _, item := range firewalls {
		if item == nil {
			continue
		}
		serverName, ok := sqlServerName(safeString(item.ID))
		server := byName[strings.ToLower(serverName)]
		if !ok || server == nil {
			continue
		}
		props := propMap(item.Properties)
		start := strings.TrimSpace(propString(props, "startIpAddress"))
		end := strings.TrimSpace(propString(props, "endIpAddress"))
		if start == "" || end == "" {
			continue
		}
		server.rules = append(server.rules, sqlFirewall{start: start, end: end})
	}
	for _, item := range vnetRules {
		if item == nil {
			continue
		}
		serverName, ok := sqlServerName(safeString(item.ID))
		server := byName[strings.ToLower(serverName)]
		if !ok || server == nil {
			continue
		}
		subnet := strings.TrimSpace(propString(propMap(item.Properties), "virtualNetworkSubnetId"))
		if subnet == "" {
			continue
		}
		server.subnets = append(server.subnets, subnet)
	}
	var model []sqlServer
	for _, key := range ordered {
		server := byName[key]
		server.publicAccess = server.publicEndpoint && firewallOpensInternet(server.rules)
		model = append(model, *server)
	}
	return model
}

func (c *Collector) addSQLNodes(batch *graph.Batch, servers []sqlServer) {
	for i := range servers {
		server := &servers[i]
		if server.location == "" {
			server.location = c.Location
		}
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        c.nodeID("datastore", server.name),
			Type:      graph.NodeDatastore,
			Name:      server.name,
			Provider:  "azure",
			Region:    server.location,
			AccountID: c.SubscriptionID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":   server.resourceID,
				"service":       "sql",
				"public_access": server.publicAccess,
			}),
		})
	}
}

func (c *Collector) linkAzureSQL(batch *graph.Batch, servers []sqlServer, workloads []azureWorkloadNet) {
	for _, server := range servers {
		datastoreID := c.nodeID("datastore", server.name)
		for _, workload := range workloads {
			via, ok := sqlAllowsWorkload(server, workload)
			if !ok {
				continue
			}
			addEdge(batch, graph.Edge{
				ID:       c.edgeID(workload.WorkloadID, datastoreID, graph.EdgeCanAccess),
				SourceID: workload.WorkloadID,
				TargetID: datastoreID,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"reason": fmt.Sprintf("%s can reach Azure SQL server %s via %s.", nodeName(batch, workload.WorkloadID), server.name, via),
				}),
			})
		}
	}
}

func sqlAllowsWorkload(server sqlServer, workload azureWorkloadNet) (string, bool) {
	if workload.WorkloadID == "" {
		return "", false
	}
	for _, have := range workload.SubnetIDs {
		for _, want := range server.subnets {
			if have != "" && strings.EqualFold(have, want) {
				return "subnet " + want, true
			}
		}
	}
	if !server.publicEndpoint {
		return "", false
	}
	for _, ip := range workload.PublicIPs {
		for _, rule := range server.rules {
			if ipv4InRange(ip, rule.start, rule.end) {
				return fmt.Sprintf("firewall %s-%s", rule.start, rule.end), true
			}
		}
	}
	return "", false
}

func firewallOpensInternet(rules []sqlFirewall) bool {
	for _, rule := range rules {
		if rule.start == "0.0.0.0" && rule.end == "255.255.255.255" {
			return true
		}
	}
	return false
}

func sqlServerName(id string) (string, bool) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "servers") && !strings.EqualFold(parts[i+1], "firewallRules") && !strings.EqualFold(parts[i+1], "virtualNetworkRules") {
			if parts[i+1] == "" {
				return "", false
			}
			return parts[i+1], true
		}
	}
	return "", false
}

func propMap(props any) map[string]any {
	m, _ := props.(map[string]any)
	return m
}

func propString(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	value, _ := props[key].(string)
	return value
}

func ipv4InRange(ip, start, end string) bool {
	target := parseIPv4(ip)
	from := parseIPv4(start)
	to := parseIPv4(end)
	if target == nil || from == nil || to == nil {
		return false
	}
	return bytesCompare(target, from) >= 0 && bytesCompare(target, to) <= 0
}

func parseIPv4(s string) net.IP {
	parsed := net.ParseIP(strings.TrimSpace(s))
	if parsed == nil {
		return nil
	}
	return parsed.To4()
}

func bytesCompare(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
