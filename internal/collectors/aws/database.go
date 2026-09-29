// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// workloadNetwork is an EC2 instance and the network facts used to decide
// whether it can open a path to an RDS instance.
type workloadNetwork struct {
	id        string
	name      string
	vpcID     string
	privateIP string
	groupIDs  []string
}

// rdsDB is one RDS or Aurora DB instance. Aurora clusters are not a second
// node; an Aurora instance is already an RDS DB instance.
type rdsDB struct {
	id       string
	name     string
	vpcID    string
	port     int32
	groupIDs []string
}

// rdsAPI is the RDS operation the collector pages.
type rdsAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

var _ rdsAPI = (*rds.Client)(nil)

// collectRDS adds a Datastore for each DB instance in the scan region and
// CAN_ACCESS edges from workloads that share its VPC and are allowed by a
// security group. A world-open group in another VPC is not a path. VPC peering
// and prefix lists are not evaluated.
func (c *Collector) collectRDS(ctx context.Context, client rdsAPI, batch *graph.Batch, groups map[string]ec2types.SecurityGroup, workloads []workloadNetwork) error {
	var dbs []rdsDB
	marker := aws.String("")
	seen := map[string]struct{}{"": {}}
	for {
		input := &rds.DescribeDBInstancesInput{}
		if aws.ToString(marker) != "" {
			input.Marker = marker
		}
		out, err := client.DescribeDBInstances(ctx, input)
		if err != nil {
			return fmt.Errorf("describe db instances: %w", err)
		}
		if out == nil {
			break
		}
		for _, instance := range out.DBInstances {
			if db, ok := c.recordRDS(batch, instance, groups); ok {
				dbs = append(dbs, db)
			}
		}
		next := aws.ToString(out.Marker)
		if next == "" {
			break
		}
		if _, ok := seen[next]; ok {
			return fmt.Errorf("describe db instances: repeated marker %q", next)
		}
		seen[next] = struct{}{}
		marker = out.Marker
	}
	c.linkRDSAccess(batch, dbs, workloads, groups)
	return nil
}

func (c *Collector) recordRDS(batch *graph.Batch, instance rdstypes.DBInstance, groups map[string]ec2types.SecurityGroup) (rdsDB, bool) {
	name := aws.ToString(instance.DBInstanceIdentifier)
	if name == "" {
		return rdsDB{}, false
	}
	port := int32(0)
	if instance.Endpoint != nil && instance.Endpoint.Port != nil {
		port = *instance.Endpoint.Port
	}
	var groupIDs []string
	for _, membership := range instance.VpcSecurityGroups {
		id := aws.ToString(membership.VpcSecurityGroupId)
		if id == "" {
			continue
		}
		status := aws.ToString(membership.Status)
		if status != "" && !strings.EqualFold(status, "active") {
			continue
		}
		groupIDs = append(groupIDs, id)
	}
	vpcID := ""
	if instance.DBSubnetGroup != nil {
		vpcID = aws.ToString(instance.DBSubnetGroup.VpcId)
	}
	public := aws.ToBool(instance.PubliclyAccessible) && rdsSecurityGroupsAllowInternet(groupIDs, groups, port)
	resourceID := aws.ToString(instance.DBInstanceArn)
	if resourceID == "" {
		resourceID = name
	}
	nodeID := c.nodeID("datastore", name)
	props := map[string]any{
		"resource_id":   resourceID,
		"service":       "rds",
		"engine":        aws.ToString(instance.Engine),
		"public_access": public,
	}
	if port > 0 {
		props["port"] = int(port)
	}
	if vpcID != "" {
		props["vpc_id"] = vpcID
	}
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID:         nodeID,
		Type:       graph.NodeDatastore,
		Name:       name,
		Provider:   "aws",
		Region:     c.Region,
		AccountID:  c.AccountID,
		Properties: graph.MustProperties(props),
	})
	return rdsDB{id: nodeID, name: name, vpcID: vpcID, port: port, groupIDs: groupIDs}, true
}

func (c *Collector) linkRDSAccess(batch *graph.Batch, dbs []rdsDB, workloads []workloadNetwork, groups map[string]ec2types.SecurityGroup) {
	for _, db := range dbs {
		for _, workload := range workloads {
			sgID, ok := rdsAllowsWorkload(db, workload, groups)
			if !ok {
				continue
			}
			workloadName := workload.name
			if workloadName == "" {
				workloadName = workload.id
			}
			addEdge(batch, graph.Edge{
				ID:       c.edgeID(workload.id, db.id, graph.EdgeCanAccess),
				SourceID: workload.id,
				TargetID: db.id,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"reason": fmt.Sprintf("Security group %s allows %s to reach %s on tcp/%d in %s.", sgID, workloadName, db.name, db.port, db.vpcID),
				}),
			})
		}
	}
}

// rdsAllowsWorkload reports the security group that permits the workload.
// The workload and the database must share a VPC. A rule matches when it
// covers the instance port and either references one of the workload's
// security groups or contains the workload's private IPv4 address.
func rdsAllowsWorkload(db rdsDB, workload workloadNetwork, groups map[string]ec2types.SecurityGroup) (string, bool) {
	if db.vpcID == "" || workload.vpcID == "" || db.vpcID != workload.vpcID || workload.id == "" {
		return "", false
	}
	for _, id := range db.groupIDs {
		sg, ok := groups[id]
		if !ok {
			continue
		}
		if securityGroupAllowsWorkload(sg, db.port, workload) {
			return id, true
		}
	}
	return "", false
}

func rdsSecurityGroupsAllowInternet(groupIDs []string, groups map[string]ec2types.SecurityGroup, port int32) bool {
	for _, id := range groupIDs {
		sg, ok := groups[id]
		if !ok {
			continue
		}
		if securityGroupAllowsInternetOnPort(sg, port) {
			return true
		}
	}
	return false
}

func securityGroupAllowsInternetOnPort(sg ec2types.SecurityGroup, port int32) bool {
	for _, perm := range sg.IpPermissions {
		if !permissionCoversPort(perm, port) {
			continue
		}
		for _, ipRange := range perm.IpRanges {
			if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
				return true
			}
		}
		for _, ipRange := range perm.Ipv6Ranges {
			if aws.ToString(ipRange.CidrIpv6) == "::/0" {
				return true
			}
		}
	}
	return false
}

func securityGroupAllowsWorkload(sg ec2types.SecurityGroup, port int32, workload workloadNetwork) bool {
	for _, perm := range sg.IpPermissions {
		if !permissionCoversPort(perm, port) {
			continue
		}
		for _, pair := range perm.UserIdGroupPairs {
			source := aws.ToString(pair.GroupId)
			if source != "" && containsString(workload.groupIDs, source) {
				return true
			}
		}
		for _, ipRange := range perm.IpRanges {
			if cidrContains(aws.ToString(ipRange.CidrIp), workload.privateIP) {
				return true
			}
		}
	}
	return false
}

func permissionCoversPort(perm ec2types.IpPermission, port int32) bool {
	proto := strings.ToLower(aws.ToString(perm.IpProtocol))
	if proto == "-1" || proto == "all" {
		return true
	}
	if proto != "tcp" && proto != "6" {
		return false
	}
	if port <= 0 || perm.FromPort == nil || perm.ToPort == nil {
		return false
	}
	return port >= *perm.FromPort && port <= *perm.ToPort
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
