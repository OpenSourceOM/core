// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func TestRDSFollowsNetworkPath(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	groups := map[string]ec2types.SecurityGroup{
		"sg-db":     testDBSecurityGroup("sg-db", "sg-web", 5432),
		"sg-open":   testCIDRSecurityGroup("sg-open", "0.0.0.0/0", 5432),
		"sg-subnet": testCIDRSecurityGroup("sg-subnet", "10.0.0.0/24", 5432),
		"sg-ssh":    testCIDRSecurityGroup("sg-ssh", "0.0.0.0/0", 22),
	}
	client := &fakeRDS{
		pages: map[string]dbPage{
			"": {next: "page-2", items: []rdstypes.DBInstance{
				testDB("open", "vpc-1", 5432, true, "sg-open"),
			}},
			"page-2": {items: []rdstypes.DBInstance{
				testDB("prod", "vpc-1", 5432, false, "sg-db"),
				testDB("subnet", "vpc-1", 5432, false, "sg-subnet"),
				testDB("closed", "vpc-1", 5432, true, "sg-ssh"),
				testDB("elsewhere", "vpc-2", 5432, true, "sg-open"),
			}},
		},
	}
	web := workloadNetwork{id: c.nodeID("workload", "i-web"), name: "web", vpcID: "vpc-1", privateIP: "10.0.0.5", groupIDs: []string{"sg-web"}}
	other := workloadNetwork{id: c.nodeID("workload", "i-other"), name: "other", vpcID: "vpc-1", privateIP: "10.0.1.8", groupIDs: []string{"sg-app"}}
	foreign := workloadNetwork{id: c.nodeID("workload", "i-foreign"), name: "foreign", vpcID: "vpc-2", privateIP: "10.1.0.5", groupIDs: []string{"sg-web"}}

	var batch graph.Batch
	if err := c.collectRDS(context.Background(), client, &batch, groups, []workloadNetwork{web, other, foreign}); err != nil {
		t.Fatal(err)
	}

	prodID := c.nodeID("datastore", "prod")
	openID := c.nodeID("datastore", "open")
	subnetID := c.nodeID("datastore", "subnet")
	closedID := c.nodeID("datastore", "closed")
	elsewhereID := c.nodeID("datastore", "elsewhere")
	for _, id := range []string{prodID, openID, subnetID, closedID, elsewhereID} {
		node, ok := nodeByID(batch, id)
		if !ok {
			t.Fatalf("missing datastore %s", id)
		}
		if node.Properties["service"] != "rds" {
			t.Fatalf("%s service = %v", id, node.Properties["service"])
		}
	}
	if got := nodeByIDMust(t, batch, prodID).Properties["public_access"]; got != false {
		t.Fatalf("prod public_access = %v", got)
	}
	if got := nodeByIDMust(t, batch, openID).Properties["public_access"]; got != true {
		t.Fatalf("open public_access = %v", got)
	}
	if got := nodeByIDMust(t, batch, closedID).Properties["public_access"]; got != false {
		t.Fatalf("publicly accessible instance whose group allows only ssh should stay private, got %v", got)
	}
	if got := nodeByIDMust(t, batch, elsewhereID).Properties["public_access"]; got != true {
		t.Fatalf("elsewhere public_access = %v", got)
	}

	if !hasEdge(batch, web.id, prodID, graph.EdgeCanAccess) {
		t.Fatal("web should reach prod through the referenced security group")
	}
	if hasEdge(batch, other.id, prodID, graph.EdgeCanAccess) || hasEdge(batch, foreign.id, prodID, graph.EdgeCanAccess) {
		t.Fatal("prod should not be reachable from a different security group or VPC")
	}
	if !hasEdge(batch, web.id, openID, graph.EdgeCanAccess) || !hasEdge(batch, other.id, openID, graph.EdgeCanAccess) {
		t.Fatal("a world-open group should allow every workload in the same VPC")
	}
	if hasEdge(batch, foreign.id, openID, graph.EdgeCanAccess) {
		t.Fatal("a world-open group in another VPC is not a path")
	}
	if !hasEdge(batch, web.id, subnetID, graph.EdgeCanAccess) {
		t.Fatal("10.0.0.5 should match 10.0.0.0/24")
	}
	if hasEdge(batch, other.id, subnetID, graph.EdgeCanAccess) {
		t.Fatal("10.0.1.8 should not match 10.0.0.0/24")
	}
	if hasEdge(batch, web.id, closedID, graph.EdgeCanAccess) {
		t.Fatal("an ssh rule should not open the database port")
	}
	if !hasEdge(batch, foreign.id, elsewhereID, graph.EdgeCanAccess) || hasEdge(batch, web.id, elsewhereID, graph.EdgeCanAccess) {
		t.Fatal("elsewhere should be reachable only from its own VPC")
	}
}

type dbPage struct {
	next  string
	items []rdstypes.DBInstance
}

type fakeRDS struct {
	pages map[string]dbPage
}

func (f *fakeRDS) DescribeDBInstances(_ context.Context, params *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	page, ok := f.pages[aws.ToString(params.Marker)]
	if !ok {
		return nil, fmt.Errorf("unexpected marker %q", aws.ToString(params.Marker))
	}
	out := &rds.DescribeDBInstancesOutput{DBInstances: page.items}
	if page.next != "" {
		out.Marker = aws.String(page.next)
	}
	return out, nil
}

func testDB(name, vpc string, port int32, public bool, groupID string) rdstypes.DBInstance {
	return rdstypes.DBInstance{
		DBInstanceIdentifier: aws.String(name),
		DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:111122223333:db:" + name),
		Engine:               aws.String("postgres"),
		PubliclyAccessible:   aws.Bool(public),
		Endpoint:             &rdstypes.Endpoint{Port: aws.Int32(port)},
		DBSubnetGroup:        &rdstypes.DBSubnetGroup{VpcId: aws.String(vpc)},
		VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{
			VpcSecurityGroupId: aws.String(groupID),
			Status:             aws.String("active"),
		}},
	}
}

func testDBSecurityGroup(id, sourceGroup string, port int32) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{
		GroupId: aws.String(id),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(port),
			ToPort:     aws.Int32(port),
			UserIdGroupPairs: []ec2types.UserIdGroupPair{{
				GroupId: aws.String(sourceGroup),
			}},
		}},
	}
}

func testCIDRSecurityGroup(id, cidr string, port int32) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{
		GroupId: aws.String(id),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(port),
			ToPort:     aws.Int32(port),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(cidr)}},
		}},
	}
}

func nodeByIDMust(t *testing.T, batch graph.Batch, id string) graph.Node {
	t.Helper()
	node, ok := nodeByID(batch, id)
	if !ok {
		t.Fatalf("missing node %s", id)
	}
	return node
}
