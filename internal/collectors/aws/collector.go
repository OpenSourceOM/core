// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Collector struct {
	Region    string
	AccountID string
}

func NewCollector(ctx context.Context, region string) (*Collector, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}

	return &Collector{
		Region:    region,
		AccountID: aws.ToString(identity.Account),
	}, nil
}

func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.Region))
	if err != nil {
		return graph.Batch{}, err
	}

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:       graph.InternetNodeID,
				Type:     graph.NodeInternet,
				Name:     "Internet",
				Provider: "aws",
			},
		},
	}

	ec2Client := ec2.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	securityGroups := map[string]ec2types.SecurityGroup{}
	var profiles []instanceProfileUse
	var networks []workloadNetwork

	if err := c.collectSecurityGroups(ctx, ec2Client, &batch, securityGroups); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectEC2(ctx, ec2Client, &batch, securityGroups, &profiles, &networks); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectIAM(ctx, iamClient, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectS3(ctx, s3Client, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectRDS(ctx, rds.NewFromConfig(cfg), &batch, securityGroups, networks); err != nil {
		return graph.Batch{}, err
	}
	if err := c.linkInstanceProfileAccess(ctx, iamClient, &batch, profiles); err != nil {
		return graph.Batch{}, err
	}

	return batch, nil
}

// s3API is the S3 operations the collector pages and reads.
type s3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
}

// iamAPI is the IAM operations used to list roles, users, and their policies.
type iamAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

var (
	_ s3API  = (*s3.Client)(nil)
	_ iamAPI = (*iam.Client)(nil)
)

func (c *Collector) collectSecurityGroups(ctx context.Context, client ec2.DescribeSecurityGroupsAPIClient, batch *graph.Batch, groups map[string]ec2types.SecurityGroup) error {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe security groups: %w", err)
		}

		for _, sg := range out.SecurityGroups {
			sgID := aws.ToString(sg.GroupId)
			internetFacing := securityGroupAllowsInternetIngress(sg)
			groups[sgID] = sg
			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        c.nodeID("network", sgID),
				Type:      graph.NodeNetwork,
				Name:      aws.ToString(sg.GroupName),
				Provider:  "aws",
				Region:    c.Region,
				AccountID: c.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"resource_id":     sgID,
					"internet_facing": internetFacing,
					"open_ingress":    internetFacing,
					"vpc_id":          aws.ToString(sg.VpcId),
				}),
			})
		}
	}
	return nil
}

func (c *Collector) collectEC2(ctx context.Context, client ec2.DescribeInstancesAPIClient, batch *graph.Batch, groups map[string]ec2types.SecurityGroup, profiles *[]instanceProfileUse, networks *[]workloadNetwork) error {
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe instances: %w", err)
		}

		for _, reservation := range out.Reservations {
			for _, instance := range reservation.Instances {
				if instance.InstanceId == nil {
					continue
				}
				instanceID := aws.ToString(instance.InstanceId)
				name := instanceName(instance)
				workloadID := c.nodeID("workload", instanceID)

				batch.Nodes = append(batch.Nodes, graph.Node{
					ID:        workloadID,
					Type:      graph.NodeWorkload,
					Name:      name,
					Provider:  "aws",
					Region:    c.Region,
					AccountID: c.AccountID,
					Properties: graph.MustProperties(map[string]any{
						"resource_id":       instanceID,
						"instance_type":     string(instance.InstanceType),
						"state":             string(instance.State.Name),
						"public_ip":         instanceHasPublicIP(instance),
						"public_ip_address": aws.ToString(instance.PublicIpAddress),
						"imdsv2":            instanceIMDSv2Required(instance),
						"os_platform":       ec2Platform(instance),
					}),
				})

				if instance.IamInstanceProfile != nil {
					if arn := aws.ToString(instance.IamInstanceProfile.Arn); arn != "" {
						*profiles = append(*profiles, instanceProfileUse{
							workloadID: workloadID,
							profileARN: arn,
						})
					}
				}

				var attached []ec2types.SecurityGroup
				var groupIDs []string
				viaGroup := ""
				for _, sgRef := range instance.SecurityGroups {
					sgID := aws.ToString(sgRef.GroupId)
					if sgID != "" {
						groupIDs = append(groupIDs, sgID)
					}
					sgNodeID := c.nodeID("network", sgID)
					batch.Edges = append(batch.Edges, graph.Edge{
						ID:       c.edgeID(workloadID, sgNodeID, graph.EdgeAffects),
						SourceID: workloadID,
						TargetID: sgNodeID,
						Type:     graph.EdgeAffects,
					})
					sg, ok := groups[sgID]
					if !ok {
						continue
					}
					attached = append(attached, sg)
					if viaGroup == "" && securityGroupAllowsInternetIngress(sg) {
						viaGroup = sgID
					}
				}
				if networks != nil {
					*networks = append(*networks, workloadNetwork{
						id:        workloadID,
						name:      name,
						vpcID:     aws.ToString(instance.VpcId),
						privateIP: aws.ToString(instance.PrivateIpAddress),
						groupIDs:  groupIDs,
					})
				}
				if instanceInternetReachable(instance, attached) {
					batch.Edges = append(batch.Edges, graph.Edge{
						ID:       c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
						SourceID: graph.InternetNodeID,
						TargetID: workloadID,
						Type:     graph.EdgeReachable,
						Properties: graph.MustProperties(map[string]any{
							"via_security_group": viaGroup,
						}),
					})
				}
			}
		}
	}
	return nil
}

func (c *Collector) collectIAM(ctx context.Context, client iamAPI, batch *graph.Batch) error {
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list iam roles: %w", err)
		}
		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)
			roleID := c.globalNodeID("identity", roleName)
			adminAccess, err := c.principalAdmin(ctx, client, "role", roleName)
			if err != nil {
				return err
			}

			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        roleID,
				Type:      graph.NodeIdentity,
				Name:      roleName,
				Provider:  "aws",
				AccountID: c.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"arn":            aws.ToString(role.Arn),
					"principal_type": "role",
					"admin_access":   adminAccess,
				}),
			})
		}
	}
	return c.collectIAMUsers(ctx, client, batch)
}

func (c *Collector) collectIAMUsers(ctx context.Context, client iamAPI, batch *graph.Batch) error {
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list iam users: %w", err)
		}
		for _, user := range page.Users {
			userName := aws.ToString(user.UserName)
			userID := c.globalNodeID("identity", "user/"+userName)
			adminAccess, err := c.principalAdmin(ctx, client, "user", userName)
			if err != nil {
				return err
			}

			// A failed lookup omits the property. Writing false would make
			// cis-iam-no-mfa match a user the API did not check, and writing
			// unused_access_keys false would hide a key that was not listed.
			props := map[string]any{
				"arn":            aws.ToString(user.Arn),
				"principal_type": "user",
				"admin_access":   adminAccess,
			}
			if mfaOut, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: user.UserName}); err == nil && mfaOut != nil {
				props["mfa"] = len(mfaOut.MFADevices) > 0
			}
			if unused, ok := unusedAccessKeysChecked(ctx, client, user.UserName); ok {
				props["unused_access_keys"] = unused
			}

			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:         userID,
				Type:       graph.NodeIdentity,
				Name:       userName,
				Provider:   "aws",
				AccountID:  c.AccountID,
				Properties: graph.MustProperties(props),
			})
		}
	}
	return nil
}

// unusedAccessKeysChecked reports whether any active key is unused.
// ok is false when listing keys or reading last-used fails, so the caller
// leaves the property unset instead of storing a control result.
func unusedAccessKeysChecked(ctx context.Context, client iamAPI, userName *string) (unused bool, ok bool) {
	keysOut, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: userName})
	if err != nil || keysOut == nil {
		return false, false
	}
	lastUsed := map[string]*time.Time{}
	for _, key := range keysOut.AccessKeyMetadata {
		if key.Status != iamtypes.StatusTypeActive {
			continue
		}
		used, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
		if err != nil || used == nil {
			return false, false
		}
		if used.AccessKeyLastUsed != nil {
			lastUsed[aws.ToString(key.AccessKeyId)] = used.AccessKeyLastUsed.LastUsedDate
		}
	}
	return unusedAccessKeys(keysOut.AccessKeyMetadata, lastUsed, 90*24*time.Hour), true
}

func (c *Collector) collectS3(ctx context.Context, client s3API, batch *graph.Batch) error {
	// MaxBuckets makes the first request paginated. An unpaginated ListBuckets
	// call is rejected once the account quota is above 10,000 buckets.
	paginator := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{
		MaxBuckets: aws.Int32(1000),
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list s3 buckets: %w", err)
		}

		for _, bucket := range out.Buckets {
			bucketName := aws.ToString(bucket.Name)
			bucketID := c.globalNodeID("datastore", bucketName)

			publicAccessBlock := "disabled"
			if blockOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
				Bucket: bucket.Name,
			}); err == nil && blockOut.PublicAccessBlockConfiguration != nil {
				cfg := blockOut.PublicAccessBlockConfiguration
				if cfg.BlockPublicAcls != nil && cfg.BlockPublicPolicy != nil &&
					cfg.IgnorePublicAcls != nil && cfg.RestrictPublicBuckets != nil {
					fullyBlocked := *cfg.BlockPublicAcls && *cfg.BlockPublicPolicy &&
						*cfg.IgnorePublicAcls && *cfg.RestrictPublicBuckets
					publicAccessBlock = s3PublicAccessBlock(true, fullyBlocked)
				}
			}

			publicAccess := false
			if aclOut, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: bucket.Name}); err == nil {
				publicAccess = s3ACLGrantsAnonymousRead(aclOut.Grants)
			}
			if !publicAccess {
				if polOut, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: bucket.Name}); err == nil {
					grants, err := s3PolicyGrantsAnonymousRead(aws.ToString(polOut.Policy))
					if err == nil && grants {
						publicAccess = true
					}
				}
			}

			encryption := false
			if encOut, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket.Name}); err == nil {
				encryption = s3EncryptionEnabled(encOut)
			}

			versioning := false
			if verOut, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket.Name}); err == nil {
				versioning = s3VersioningEnabled(verOut)
			}

			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        bucketID,
				Type:      graph.NodeDatastore,
				Name:      bucketName,
				Provider:  "aws",
				AccountID: c.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"resource_id":         bucketName,
					"service":             "s3",
					"public_access":       publicAccess,
					"public_access_block": publicAccessBlock,
					"encryption":          encryption,
					"versioning":          versioning,
				}),
			})
		}
	}
	return nil
}

func ec2Platform(instance ec2types.Instance) string {
	if instance.PlatformDetails != nil && *instance.PlatformDetails != "" {
		return *instance.PlatformDetails
	}
	if instance.Platform != "" {
		return string(instance.Platform)
	}
	return "linux/unix"
}

func (c *Collector) nodeID(kind, resource string) string {
	return fmt.Sprintf("aws:%s:%s:%s:%s", c.AccountID, c.Region, kind, resource)
}

// globalNodeID is the account-scoped id for IAM principals and S3 buckets.
// A second regional scan updates these nodes instead of creating another copy.
func (c *Collector) globalNodeID(kind, resource string) string {
	return fmt.Sprintf("aws:%s:global:%s:%s", c.AccountID, kind, resource)
}

func (c *Collector) edgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, edgeType)
}

func instanceName(instance ec2types.Instance) string {
	for _, tag := range instance.Tags {
		if aws.ToString(tag.Key) == "Name" && tag.Value != nil {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(instance.InstanceId)
}

func securityGroupAllowsInternetIngress(sg ec2types.SecurityGroup) bool {
	for _, perm := range sg.IpPermissions {
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

// principalAdmin reports whether an IAM user or role has full admin from an
// attached or inline policy. Group policies are not included.
func (c *Collector) principalAdmin(ctx context.Context, client iamAPI, kind, name string) (bool, error) {
	var (
		docs []string
		err  error
	)
	switch kind {
	case "role":
		docs, err = c.rolePolicyDocuments(ctx, client, name)
	case "user":
		docs, err = c.userPolicyDocuments(ctx, client, name)
	default:
		return false, fmt.Errorf("unknown principal kind %q", kind)
	}
	if err != nil {
		return false, err
	}
	return documentsGrantAdmin(docs)
}
