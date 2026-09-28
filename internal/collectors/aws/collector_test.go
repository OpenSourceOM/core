// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestCollectFollowsPagination(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	ec2Client := &fakeEC2{
		instances: map[string]instancePage{
			"": {
				next: "instances-2",
				items: []ec2types.Instance{
					testInstance("i-1", "", "sg-1"),
				},
			},
			"instances-2": {
				items: []ec2types.Instance{
					testInstance("i-2", "203.0.113.10", "sg-2"),
				},
			},
		},
		groups: map[string]groupPage{
			"": {
				next: "groups-2",
				items: []ec2types.SecurityGroup{
					testSecurityGroup("sg-1", false),
				},
			},
			"groups-2": {
				items: []ec2types.SecurityGroup{
					testSecurityGroup("sg-2", true),
				},
			},
		},
	}
	buckets := &fakeS3{
		pages: map[string]bucketPage{
			"": {
				next:  "buckets-2",
				items: []s3types.Bucket{{Name: aws.String("alpha")}},
			},
			"buckets-2": {
				items: []s3types.Bucket{{Name: aws.String("beta")}},
			},
		},
	}

	var batch graph.Batch
	groups := map[string]ec2types.SecurityGroup{}
	var profiles []instanceProfileUse
	ctx := context.Background()
	if err := c.collectSecurityGroups(ctx, ec2Client, &batch, groups); err != nil {
		t.Fatal(err)
	}
	if err := c.collectEC2(ctx, ec2Client, &batch, groups, &profiles); err != nil {
		t.Fatal(err)
	}
	if err := c.collectS3(ctx, buckets, &batch); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{
		c.nodeID("network", "sg-1"),
		c.nodeID("network", "sg-2"),
		c.nodeID("workload", "i-1"),
		c.nodeID("workload", "i-2"),
		c.globalNodeID("datastore", "alpha"),
		c.globalNodeID("datastore", "beta"),
	} {
		if !hasNode(batch, id) {
			t.Errorf("missing node %s", id)
		}
	}

	webID := c.nodeID("workload", "i-2")
	if !hasEdge(batch, graph.InternetNodeID, webID, graph.EdgeReachable) {
		t.Fatal("instance on the second page should be reachable via the security group on the second page")
	}
	if hasEdge(batch, graph.InternetNodeID, c.nodeID("workload", "i-1"), graph.EdgeReachable) {
		t.Fatal("closed security group should not make i-1 reachable")
	}
}

func TestAccountGlobalIDsAreStableAcrossRegions(t *testing.T) {
	east := collectRegion(t, "us-east-1")
	west := collectRegion(t, "us-west-2")

	roleID := "aws:111122223333:global:identity:AdminRole"
	userID := "aws:111122223333:global:identity:user/alice"
	bucketID := "aws:111122223333:global:datastore:logs"

	for _, id := range []string{roleID, userID, bucketID} {
		eastNode, ok := nodeByID(east, id)
		if !ok {
			t.Fatalf("us-east-1 batch missing %s", id)
		}
		westNode, ok := nodeByID(west, id)
		if !ok {
			t.Fatalf("us-west-2 batch missing %s", id)
		}
		if eastNode.ID != westNode.ID {
			t.Fatalf("region scans produced different ids for %s", id)
		}
		if eastNode.Region != "" || westNode.Region != "" {
			t.Fatalf("%s stored a scan region (%q, %q)", id, eastNode.Region, westNode.Region)
		}
	}

	eastInstance := "aws:111122223333:us-east-1:workload:i-1"
	westInstance := "aws:111122223333:us-west-2:workload:i-1"
	eastGroup := "aws:111122223333:us-east-1:network:sg-1"
	westGroup := "aws:111122223333:us-west-2:network:sg-1"
	if !hasNode(east, eastInstance) || !hasNode(west, westInstance) {
		t.Fatal("EC2 ids should stay regional")
	}
	if hasNode(east, westInstance) || hasNode(west, eastInstance) {
		t.Fatal("EC2 ids must not be shared across regions")
	}
	if !hasNode(east, eastGroup) || !hasNode(west, westGroup) {
		t.Fatal("security group ids should stay regional")
	}
	if hasNode(east, westGroup) || hasNode(west, eastGroup) {
		t.Fatal("security group ids must not be shared across regions")
	}
	if node, ok := nodeByID(east, eastInstance); !ok || node.Region != "us-east-1" {
		t.Fatal("EC2 node should keep the scan region")
	}
}

func collectRegion(t *testing.T, region string) graph.Batch {
	t.Helper()
	c := &Collector{Region: region, AccountID: "111122223333"}
	var batch graph.Batch
	ctx := context.Background()
	if err := c.collectIAM(ctx, &fakeIAM{}, &batch); err != nil {
		t.Fatal(err)
	}
	if err := c.collectS3(ctx, &fakeS3{
		pages: map[string]bucketPage{
			"": {items: []s3types.Bucket{{Name: aws.String("logs")}}},
		},
	}, &batch); err != nil {
		t.Fatal(err)
	}
	groups := map[string]ec2types.SecurityGroup{}
	ec2Client := &fakeEC2{
		instances: map[string]instancePage{
			"": {items: []ec2types.Instance{testInstance("i-1", "", "sg-1")}},
		},
		groups: map[string]groupPage{
			"": {items: []ec2types.SecurityGroup{testSecurityGroup("sg-1", false)}},
		},
	}
	if err := c.collectSecurityGroups(ctx, ec2Client, &batch, groups); err != nil {
		t.Fatal(err)
	}
	var profiles []instanceProfileUse
	if err := c.collectEC2(ctx, ec2Client, &batch, groups, &profiles); err != nil {
		t.Fatal(err)
	}
	return batch
}

type instancePage struct {
	next  string
	items []ec2types.Instance
}

type groupPage struct {
	next  string
	items []ec2types.SecurityGroup
}

type fakeEC2 struct {
	instances map[string]instancePage
	groups    map[string]groupPage
}

func (f *fakeEC2) DescribeInstances(_ context.Context, params *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	page, ok := f.instances[aws.ToString(params.NextToken)]
	if !ok {
		return nil, fmt.Errorf("unexpected instances token %q", aws.ToString(params.NextToken))
	}
	out := &ec2.DescribeInstancesOutput{}
	if page.next != "" {
		out.NextToken = aws.String(page.next)
	}
	if len(page.items) > 0 {
		out.Reservations = []ec2types.Reservation{{Instances: page.items}}
	}
	return out, nil
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, params *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	page, ok := f.groups[aws.ToString(params.NextToken)]
	if !ok {
		return nil, fmt.Errorf("unexpected security group token %q", aws.ToString(params.NextToken))
	}
	out := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: page.items}
	if page.next != "" {
		out.NextToken = aws.String(page.next)
	}
	return out, nil
}

type bucketPage struct {
	next  string
	items []s3types.Bucket
}

type fakeS3 struct {
	pages map[string]bucketPage
}

func (f *fakeS3) ListBuckets(_ context.Context, params *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	page, ok := f.pages[aws.ToString(params.ContinuationToken)]
	if !ok {
		return nil, fmt.Errorf("unexpected buckets token %q", aws.ToString(params.ContinuationToken))
	}
	out := &s3.ListBucketsOutput{Buckets: page.items}
	if page.next != "" {
		out.ContinuationToken = aws.String(page.next)
	}
	return out, nil
}

func (f *fakeS3) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return nil, errors.New("not configured")
}

func (f *fakeS3) GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return nil, errors.New("not configured")
}

func (f *fakeS3) GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return nil, errors.New("not configured")
}

func (f *fakeS3) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return nil, errors.New("not configured")
}

func (f *fakeS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return nil, errors.New("not configured")
}

func TestAdminAccessFollowsPolicies(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	const (
		administratorAccess = "arn:aws:iam::aws:policy/AdministratorAccess"
		readOnly            = "arn:aws:iam::aws:policy/ReadOnlyAccess"
		readOnlyDoc         = `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
		starDoc             = `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	)
	client := &fakeIAM{
		roles: []iamtypes.Role{
			{RoleName: aws.String("Admin"), Arn: aws.String("arn:aws:iam::111122223333:role/Admin")},
			{RoleName: aws.String("app"), Arn: aws.String("arn:aws:iam::111122223333:role/app")},
			{RoleName: aws.String("worker"), Arn: aws.String("arn:aws:iam::111122223333:role/worker")},
		},
		users: []iamtypes.User{
			{UserName: aws.String("Admin"), Arn: aws.String("arn:aws:iam::111122223333:user/Admin")},
			{UserName: aws.String("ops"), Arn: aws.String("arn:aws:iam::111122223333:user/ops")},
			{UserName: aws.String("breakglass"), Arn: aws.String("arn:aws:iam::111122223333:user/breakglass")},
		},
		attachedRoles: map[string][]iamtypes.AttachedPolicy{
			"Admin": {{
				PolicyName: aws.String("ReadOnlyAccess"),
				PolicyArn:  aws.String(readOnly),
			}},
			"app": {{
				PolicyName: aws.String("AdministratorAccess"),
				PolicyArn:  aws.String(administratorAccess),
			}},
		},
		inlineRoles: map[string]map[string]string{
			"worker": {"full": starDoc},
		},
		attachedUsers: map[string][]iamtypes.AttachedPolicy{
			"ops": {{
				PolicyName: aws.String("AdministratorAccess"),
				PolicyArn:  aws.String(administratorAccess),
			}},
		},
		inlineUsers: map[string]map[string]string{
			"breakglass": {"full": starDoc},
		},
		managedDocs: map[string]string{
			readOnly: readOnlyDoc,
		},
	}

	var batch graph.Batch
	if err := c.collectIAM(context.Background(), client, &batch); err != nil {
		t.Fatal(err)
	}

	assertAdmin := func(id string, want bool) {
		t.Helper()
		node, ok := nodeByID(batch, id)
		if !ok {
			t.Fatalf("missing node %s", id)
		}
		got, _ := node.Properties["admin_access"].(bool)
		if got != want {
			t.Fatalf("%s admin_access = %v, want %v", node.Name, got, want)
		}
	}
	assertAdmin(c.globalNodeID("identity", "Admin"), false)
	assertAdmin(c.globalNodeID("identity", "app"), true)
	assertAdmin(c.globalNodeID("identity", "worker"), true)
	assertAdmin(c.globalNodeID("identity", "user/Admin"), false)
	assertAdmin(c.globalNodeID("identity", "user/ops"), true)
	assertAdmin(c.globalNodeID("identity", "user/breakglass"), true)
	for _, arn := range client.fetchedPolicies {
		if arn == administratorAccess {
			t.Fatal("AdministratorAccess should count without GetPolicy")
		}
	}
	if len(client.fetchedPolicies) != 1 || client.fetchedPolicies[0] != readOnly {
		t.Fatalf("fetched policies = %v, want only ReadOnlyAccess", client.fetchedPolicies)
	}
}

func TestAdminAccessLookupError(t *testing.T) {
	c := &Collector{Region: "us-east-1", AccountID: "111122223333"}
	client := &fakeIAM{
		roles: []iamtypes.Role{{
			RoleName: aws.String("app"),
			Arn:      aws.String("arn:aws:iam::111122223333:role/app"),
		}},
		users:     []iamtypes.User{},
		policyErr: errors.New("access denied"),
	}
	var batch graph.Batch
	if err := c.collectIAM(context.Background(), client, &batch); err == nil {
		t.Fatal("expected policy lookup error")
	}
}

type fakeIAM struct {
	roles           []iamtypes.Role
	users           []iamtypes.User
	attachedRoles   map[string][]iamtypes.AttachedPolicy
	inlineRoles     map[string]map[string]string
	attachedUsers   map[string][]iamtypes.AttachedPolicy
	inlineUsers     map[string]map[string]string
	managedDocs     map[string]string
	fetchedPolicies []string
	policyErr       error
}

func (f *fakeIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	roles := f.roles
	if roles == nil {
		roles = []iamtypes.Role{{
			RoleName: aws.String("AdminRole"),
			Arn:      aws.String("arn:aws:iam::111122223333:role/AdminRole"),
		}}
	}
	return &iam.ListRolesOutput{Roles: roles}, nil
}

func (f *fakeIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	users := f.users
	if users == nil {
		users = []iamtypes.User{{
			UserName: aws.String("alice"),
			Arn:      aws.String("arn:aws:iam::111122223333:user/alice"),
		}}
	}
	return &iam.ListUsersOutput{Users: users}, nil
}

func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, params *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: f.attachedRoles[aws.ToString(params.RoleName)],
	}, nil
}

func (f *fakeIAM) ListRolePolicies(_ context.Context, params *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	var names []string
	for name := range f.inlineRoles[aws.ToString(params.RoleName)] {
		names = append(names, name)
	}
	return &iam.ListRolePoliciesOutput{PolicyNames: names}, nil
}

func (f *fakeIAM) GetRolePolicy(_ context.Context, params *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	doc, ok := f.inlineRoles[aws.ToString(params.RoleName)][aws.ToString(params.PolicyName)]
	if !ok {
		return nil, fmt.Errorf("unknown inline policy %s on role %s", aws.ToString(params.PolicyName), aws.ToString(params.RoleName))
	}
	return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(doc)}, nil
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, params *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: f.attachedUsers[aws.ToString(params.UserName)],
	}, nil
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, params *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	var names []string
	for name := range f.inlineUsers[aws.ToString(params.UserName)] {
		names = append(names, name)
	}
	return &iam.ListUserPoliciesOutput{PolicyNames: names}, nil
}

func (f *fakeIAM) GetUserPolicy(_ context.Context, params *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	doc, ok := f.inlineUsers[aws.ToString(params.UserName)][aws.ToString(params.PolicyName)]
	if !ok {
		return nil, fmt.Errorf("unknown inline policy %s on user %s", aws.ToString(params.PolicyName), aws.ToString(params.UserName))
	}
	return &iam.GetUserPolicyOutput{PolicyDocument: aws.String(doc)}, nil
}

func (f *fakeIAM) GetPolicy(_ context.Context, params *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	arn := aws.ToString(params.PolicyArn)
	f.fetchedPolicies = append(f.fetchedPolicies, arn)
	if _, ok := f.managedDocs[arn]; !ok {
		return nil, fmt.Errorf("unknown policy %s", arn)
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn:              params.PolicyArn,
		DefaultVersionId: aws.String("v1"),
	}}, nil
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, params *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	arn := aws.ToString(params.PolicyArn)
	doc, ok := f.managedDocs[arn]
	if !ok {
		return nil, fmt.Errorf("unknown policy %s", arn)
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		Document:  aws.String(doc),
		VersionId: aws.String("v1"),
	}}, nil
}

func (f *fakeIAM) ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return nil, errors.New("lookup failed")
}

func (f *fakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return nil, errors.New("lookup failed")
}

func (f *fakeIAM) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return nil, errors.New("lookup failed")
}

func testInstance(id, publicIP, groupID string) ec2types.Instance {
	instance := ec2types.Instance{
		InstanceId:   aws.String(id),
		InstanceType: ec2types.InstanceTypeT3Micro,
		State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		SecurityGroups: []ec2types.GroupIdentifier{{
			GroupId: aws.String(groupID),
		}},
	}
	if publicIP != "" {
		instance.PublicIpAddress = aws.String(publicIP)
	}
	return instance
}

func testSecurityGroup(id string, open bool) ec2types.SecurityGroup {
	sg := ec2types.SecurityGroup{
		GroupId:   aws.String(id),
		GroupName: aws.String(id),
		VpcId:     aws.String("vpc-1"),
	}
	if open {
		sg.IpPermissions = []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}}
	}
	return sg
}

func hasNode(batch graph.Batch, id string) bool {
	_, ok := nodeByID(batch, id)
	return ok
}

func nodeByID(batch graph.Batch, id string) (graph.Node, bool) {
	for _, node := range batch.Nodes {
		if node.ID == id {
			return node, true
		}
	}
	return graph.Node{}, false
}
