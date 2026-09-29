// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

// gcpNIC is one interface on a GCE instance.
type gcpNIC struct {
	Network   string
	PrivateIP string
	PublicIPs []string
}

// gcpWorkloadNet is a GCE instance and the networks it can use to reach Cloud SQL.
// Private Service Connect is not expanded.
type gcpWorkloadNet struct {
	ID   string
	Name string
	NICs []gcpNIC
}

// collectCloudSQL adds a Datastore per Cloud SQL instance and CAN_ACCESS edges
// from instances that share its private-IP network, or whose public IP is in
// an authorized network. Same-project membership is not enough.
func (c *Collector) collectCloudSQL(ctx context.Context, batch *graph.Batch, workloads []gcpWorkloadNet) error {
	service, err := sqladmin.NewService(ctx, option.WithScopes(sqladmin.CloudPlatformScope))
	if err != nil {
		return fmt.Errorf("sql admin client: %w", err)
	}
	err = service.Instances.List(c.ProjectID).Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			c.recordCloudSQL(batch, instance, workloads)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list cloud sql instances: %w", err)
	}
	return nil
}

func (c *Collector) recordCloudSQL(batch *graph.Batch, instance *sqladmin.DatabaseInstance, workloads []gcpWorkloadNet) {
	if instance == nil || instance.Name == "" || instance.InstanceType == "ON_PREMISES_INSTANCE" {
		return
	}
	region := instance.Region
	if region == "" {
		region = c.Region
	}
	nodeID := c.nodeID(region, "datastore", instance.Name)
	resourceID := instance.ConnectionName
	if resourceID == "" {
		resourceID = instance.Name
	}
	public := cloudSQLPublic(instance)
	props := map[string]any{
		"resource_id":   resourceID,
		"service":       "cloudsql",
		"engine":        instance.DatabaseVersion,
		"public_access": public,
	}
	if instance.Settings != nil {
		graph.SetSensitivity(props, instance.Settings.UserLabels)
	}
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID:         nodeID,
		Type:       graph.NodeDatastore,
		Name:       instance.Name,
		Provider:   "gcp",
		Region:     region,
		AccountID:  c.ProjectID,
		Properties: graph.MustProperties(props),
	})
	for _, workload := range workloads {
		reason, ok := cloudSQLAllowsWorkload(instance, workload)
		if !ok || workload.ID == "" {
			continue
		}
		addEdge(batch, graph.Edge{
			ID:       c.edgeID(workload.ID, nodeID, graph.EdgeCanAccess),
			SourceID: workload.ID,
			TargetID: nodeID,
			Type:     graph.EdgeCanAccess,
			Properties: graph.MustProperties(map[string]any{
				"reason": reason,
			}),
		})
	}
}

func gcpWorkloadNetwork(c *Collector, zone string, instance *compute.Instance) (gcpWorkloadNet, bool) {
	if c == nil || instance == nil || instance.Name == "" {
		return gcpWorkloadNet{}, false
	}
	net := gcpWorkloadNet{
		ID:   c.nodeID(zone, "workload", instance.Name),
		Name: instance.Name,
	}
	for _, nic := range instance.NetworkInterfaces {
		if nic == nil {
			continue
		}
		item := gcpNIC{
			Network:   resourceName(nic.Network),
			PrivateIP: nic.NetworkIP,
		}
		for _, access := range nic.AccessConfigs {
			if access != nil && access.NatIP != "" {
				item.PublicIPs = append(item.PublicIPs, access.NatIP)
			}
		}
		net.NICs = append(net.NICs, item)
	}
	return net, true
}

func cloudSQLPublic(instance *sqladmin.DatabaseInstance) bool {
	cfg := cloudSQLIPConfig(instance)
	if cfg == nil || !cfg.Ipv4Enabled {
		return false
	}
	for _, entry := range cfg.AuthorizedNetworks {
		if entry == nil {
			continue
		}
		switch strings.TrimSpace(entry.Value) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// cloudSQLAllowsWorkload reports why the instance can reach the database.
// A private IP path is the Cloud SQL VPC. A public path is an authorized
// network that contains one of the instance's public addresses.
func cloudSQLAllowsWorkload(instance *sqladmin.DatabaseInstance, workload gcpWorkloadNet) (string, bool) {
	if instance == nil || workload.ID == "" {
		return "", false
	}
	name := workload.Name
	if name == "" {
		name = workload.ID
	}
	if network := cloudSQLPrivateNetwork(instance); network != "" {
		for _, nic := range workload.NICs {
			if nic.Network == network {
				return fmt.Sprintf("%s is on VPC %s, which has a private path to Cloud SQL %s.", name, network, instance.Name), true
			}
		}
	}
	cfg := cloudSQLIPConfig(instance)
	if cfg == nil || !cfg.Ipv4Enabled {
		return "", false
	}
	for _, nic := range workload.NICs {
		for _, ip := range nic.PublicIPs {
			for _, entry := range cfg.AuthorizedNetworks {
				if entry == nil {
					continue
				}
				if cidrContains(entry.Value, ip) {
					return fmt.Sprintf("Cloud SQL %s authorizes %s, which includes %s.", instance.Name, strings.TrimSpace(entry.Value), ip), true
				}
			}
		}
	}
	return "", false
}

func cloudSQLPrivateNetwork(instance *sqladmin.DatabaseInstance) string {
	cfg := cloudSQLIPConfig(instance)
	if cfg == nil {
		return ""
	}
	network := resourceName(cfg.PrivateNetwork)
	if network == "" {
		return ""
	}
	for _, ip := range instance.IpAddresses {
		if ip != nil && ip.Type == "PRIVATE" && ip.IpAddress != "" {
			return network
		}
	}
	return ""
}

func cloudSQLIPConfig(instance *sqladmin.DatabaseInstance) *sqladmin.IpConfiguration {
	if instance == nil || instance.Settings == nil {
		return nil
	}
	return instance.Settings.IpConfiguration
}

func cidrContains(cidr, ip string) bool {
	cidr = strings.TrimSpace(cidr)
	ip = strings.TrimSpace(ip)
	if cidr == "" || ip == "" {
		return false
	}
	target := net.ParseIP(ip)
	if target == nil {
		return false
	}
	if !strings.Contains(cidr, "/") {
		parsed := net.ParseIP(cidr)
		return parsed != nil && parsed.Equal(target)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(target)
}
