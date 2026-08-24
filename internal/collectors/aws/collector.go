// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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

	sgInternetFacing := map[string]bool{}

	if err := c.collectSecurityGroups(ctx, ec2Client, &batch, sgInternetFacing); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectEC2(ctx, ec2Client, &batch, sgInternetFacing); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectIAM(ctx, iamClient, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectS3(ctx, s3Client, &batch); err != nil {
		return graph.Batch{}, err
	}

	c.linkInternetWorkloadsToPublicDatastores(&batch)
	return batch, nil
}

func (c *Collector) collectSecurityGroups(ctx context.Context, client *ec2.Client, batch *graph.Batch, sgInternetFacing map[string]bool) error {
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return fmt.Errorf("describe security groups: %w", err)
	}

	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		internetFacing := securityGroupAllowsInternetIngress(sg)

		sgInternetFacing[sgID] = internetFacing
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        c.nodeID("network", sgID),
			Type:      graph.NodeNetwork,
			Name:      aws.ToString(sg.GroupName),
			Provider:  "aws",
			Region:    c.Region,
			AccountID: c.AccountID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":       sgID,
				"internet_facing": internetFacing,
				"vpc_id":            aws.ToString(sg.VpcId),
			}),
		})
	}
	return nil
}

func (c *Collector) collectEC2(ctx context.Context, client *ec2.Client, batch *graph.Batch, sgInternetFacing map[string]bool) error {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
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
					"resource_id": instanceID,
					"state":       string(instance.State.Name),
					"public_ip":   aws.ToString(instance.PublicIpAddress),
					"os_platform": ec2Platform(instance),
				}),
			})

			for _, sgRef := range instance.SecurityGroups {
				sgID := aws.ToString(sgRef.GroupId)
				sgNodeID := c.nodeID("network", sgID)
				batch.Edges = append(batch.Edges, graph.Edge{
					ID:       c.edgeID(workloadID, sgNodeID, graph.EdgeAffects),
					SourceID: workloadID,
					TargetID: sgNodeID,
					Type:     graph.EdgeAffects,
				})

				if sgInternetFacing[sgID] {
					batch.Edges = append(batch.Edges, graph.Edge{
						ID:       c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
						SourceID: graph.InternetNodeID,
						TargetID: workloadID,
						Type:     graph.EdgeReachable,
						Properties: graph.MustProperties(map[string]any{
							"via_security_group": sgID,
						}),
					})
				}
			}
		}
	}
	return nil
}

func (c *Collector) collectIAM(ctx context.Context, client *iam.Client, batch *graph.Batch) error {
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list iam roles: %w", err)
		}
		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)
			roleID := c.nodeID("identity", roleName)
			adminAccess := roleLooksAdministrative(roleName, aws.ToString(role.Arn))

			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        roleID,
				Type:      graph.NodeIdentity,
				Name:      roleName,
				Provider:  "aws",
				Region:    c.Region,
				AccountID: c.AccountID,
				Properties: graph.MustProperties(map[string]any{
					"arn":          aws.ToString(role.Arn),
					"admin_access": adminAccess,
				}),
			})
		}
	}
	return nil
}

func (c *Collector) collectS3(ctx context.Context, client *s3.Client, batch *graph.Batch) error {
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list s3 buckets: %w", err)
	}

	for _, bucket := range out.Buckets {
		bucketName := aws.ToString(bucket.Name)
		bucketID := c.nodeID("datastore", bucketName)

		publicAccess := false
		publicAccessBlock := "unknown"
		if blockOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		}); err == nil && blockOut.PublicAccessBlockConfiguration != nil {
			cfg := blockOut.PublicAccessBlockConfiguration
			if cfg.BlockPublicAcls != nil && cfg.BlockPublicPolicy != nil &&
				cfg.IgnorePublicAcls != nil && cfg.RestrictPublicBuckets != nil {
				fullyBlocked := *cfg.BlockPublicAcls && *cfg.BlockPublicPolicy &&
					*cfg.IgnorePublicAcls && *cfg.RestrictPublicBuckets
				publicAccessBlock = map[bool]string{true: "enabled", false: "disabled"}[!fullyBlocked]
				publicAccess = !fullyBlocked
			}
		} else {
			publicAccessBlock = "not_configured"
			publicAccess = true
		}

		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        bucketID,
			Type:      graph.NodeDatastore,
			Name:      bucketName,
			Provider:  "aws",
			Region:    c.Region,
			AccountID: c.AccountID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":         bucketName,
				"public_access":       publicAccess,
				"public_access_block": publicAccessBlock,
			}),
		})

		// Phase 0 heuristic: link admin identities to public buckets in same account.
		for _, node := range batch.Nodes {
			if node.Type != graph.NodeIdentity {
				continue
			}
			admin, _ := node.Properties["admin_access"].(bool)
			if !admin || !publicAccess {
				continue
			}
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(node.ID, bucketID, graph.EdgeCanAccess),
				SourceID: node.ID,
				TargetID: bucketID,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"heuristic": "phase0-admin-to-public-s3",
				}),
			})
		}
	}
	return nil
}

func (c *Collector) linkInternetWorkloadsToPublicDatastores(batch *graph.Batch) {
	internetWorkloads := map[string]bool{}
	for _, edge := range batch.Edges {
		if edge.SourceID == graph.InternetNodeID && edge.Type == graph.EdgeReachable {
			internetWorkloads[edge.TargetID] = true
		}
	}

	var publicDatastores []graph.Node
	for _, node := range batch.Nodes {
		if node.Type != graph.NodeDatastore {
			continue
		}
		public, _ := node.Properties["public_access"].(bool)
		if public {
			publicDatastores = append(publicDatastores, node)
		}
	}

	for _, node := range batch.Nodes {
		if node.Type != graph.NodeWorkload || !internetWorkloads[node.ID] {
			continue
		}
		for _, datastore := range publicDatastores {
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(node.ID, datastore.ID, graph.EdgeCanAccess),
				SourceID: node.ID,
				TargetID: datastore.ID,
				Type:     graph.EdgeCanAccess,
				Properties: graph.MustProperties(map[string]any{
					"heuristic": "phase1-internet-workload-to-public-datastore",
				}),
			})
		}
	}
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
		if !permissionAllowsAllIPv4(perm) {
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

func permissionAllowsAllIPv4(perm ec2types.IpPermission) bool {
	from := aws.ToInt32(perm.FromPort)
	to := aws.ToInt32(perm.ToPort)
	if perm.IpProtocol == nil {
		return false
	}
	proto := strings.ToLower(aws.ToString(perm.IpProtocol))
	if proto == "-1" {
		return true
	}
	if proto == "tcp" && from <= 443 && to >= 443 {
		return true
	}
	return false
}

func roleLooksAdministrative(name, arn string) bool {
	lower := strings.ToLower(name + " " + arn)
	keywords := []string{"admin", "poweruser", "fullaccess", "organizationaccountaccessrole"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
