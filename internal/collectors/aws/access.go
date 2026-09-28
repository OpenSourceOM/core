// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// instanceProfileUse is an EC2 instance and the instance profile attached to it.
type instanceProfileUse struct {
	workloadID string
	profileARN string
}

// linkInstanceProfileAccess adds ASSUMES edges from each instance to the role
// on its instance profile, and CAN_ACCESS edges from that role to S3 buckets
// its identity policies allow. Deny statements and conditions are not evaluated.
func (c *Collector) linkInstanceProfileAccess(ctx context.Context, client *iam.Client, batch *graph.Batch, profiles []instanceProfileUse) error {
	rolesByProfile := map[string][]instanceProfileRole{}
	docsByRole := map[string][]string{}

	for _, use := range profiles {
		if use.profileARN == "" || use.workloadID == "" {
			continue
		}
		roles, ok := rolesByProfile[use.profileARN]
		if !ok {
			resolved, err := c.instanceProfileRoles(ctx, client, use.profileARN)
			if err != nil {
				return err
			}
			roles = resolved
			rolesByProfile[use.profileARN] = roles
		}
		profileName := instanceProfileName(use.profileARN)
		for _, role := range roles {
			c.ensureRoleNode(batch, role.name, role.arn)
			addEdge(batch, graph.Edge{
				ID:       c.edgeID(use.workloadID, c.globalNodeID("identity", role.name), graph.EdgeAssumes),
				SourceID: use.workloadID,
				TargetID: c.globalNodeID("identity", role.name),
				Type:     graph.EdgeAssumes,
				Properties: graph.MustProperties(map[string]any{
					"instance_profile": profileName,
					"reason":           fmt.Sprintf("Instance profile %s attaches role %s.", profileName, role.name),
				}),
			})
			if _, loaded := docsByRole[role.name]; loaded {
				continue
			}
			docs, err := c.rolePolicyDocuments(ctx, client, role.name)
			if err != nil {
				return err
			}
			docsByRole[role.name] = docs
		}
	}

	for roleName, docs := range docsByRole {
		if err := c.linkRoleS3Access(batch, roleName, docs); err != nil {
			return err
		}
	}
	return nil
}

type instanceProfileRole struct {
	name string
	arn  string
}

func (c *Collector) instanceProfileRoles(ctx context.Context, client *iam.Client, profileARN string) ([]instanceProfileRole, error) {
	name := instanceProfileName(profileARN)
	if name == "" {
		return nil, fmt.Errorf("instance profile ARN %q has no name", profileARN)
	}
	out, err := client.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("get instance profile %s: %w", name, err)
	}
	if out.InstanceProfile == nil {
		return nil, fmt.Errorf("get instance profile %s: empty response", name)
	}
	var roles []instanceProfileRole
	for _, role := range out.InstanceProfile.Roles {
		roleName := aws.ToString(role.RoleName)
		if roleName == "" {
			continue
		}
		roles = append(roles, instanceProfileRole{
			name: roleName,
			arn:  aws.ToString(role.Arn),
		})
	}
	return roles, nil
}

func (c *Collector) rolePolicyDocuments(ctx context.Context, client *iam.Client, roleName string) ([]string, error) {
	var docs []string

	attached := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list attached policies for %s: %w", roleName, err)
		}
		for _, policy := range page.AttachedPolicies {
			doc, err := c.managedPolicyDocument(ctx, client, aws.ToString(policy.PolicyArn))
			if err != nil {
				return nil, err
			}
			docs = append(docs, doc)
		}
	}

	inline := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list inline policies for %s: %w", roleName, err)
		}
		for _, policyName := range page.PolicyNames {
			out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				return nil, fmt.Errorf("get inline policy %s on %s: %w", policyName, roleName, err)
			}
			doc, err := decodePolicyDocument(aws.ToString(out.PolicyDocument))
			if err != nil {
				return nil, fmt.Errorf("inline policy %s on %s: %w", policyName, roleName, err)
			}
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

func (c *Collector) managedPolicyDocument(ctx context.Context, client *iam.Client, policyARN string) (string, error) {
	if policyARN == "" {
		return "", fmt.Errorf("attached policy is missing an ARN")
	}
	policy, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return "", fmt.Errorf("get policy %s: %w", policyARN, err)
	}
	if policy.Policy == nil || policy.Policy.DefaultVersionId == nil {
		return "", fmt.Errorf("get policy %s: missing default version", policyARN)
	}
	version, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return "", fmt.Errorf("get policy version %s: %w", policyARN, err)
	}
	if version.PolicyVersion == nil {
		return "", fmt.Errorf("get policy version %s: empty response", policyARN)
	}
	doc, err := decodePolicyDocument(aws.ToString(version.PolicyVersion.Document))
	if err != nil {
		return "", fmt.Errorf("policy %s: %w", policyARN, err)
	}
	return doc, nil
}

func (c *Collector) ensureRoleNode(batch *graph.Batch, roleName, roleARN string) {
	id := c.globalNodeID("identity", roleName)
	for _, node := range batch.Nodes {
		if node.ID == id {
			return
		}
	}
	batch.Nodes = append(batch.Nodes, graph.Node{
		ID:        id,
		Type:      graph.NodeIdentity,
		Name:      roleName,
		Provider:  "aws",
		AccountID: c.AccountID,
		Properties: graph.MustProperties(map[string]any{
			"arn":            roleARN,
			"principal_type": "role",
			"admin_access":   roleLooksAdministrative(roleName, roleARN),
		}),
	})
}

func (c *Collector) linkRoleS3Access(batch *graph.Batch, roleName string, docs []string) error {
	roleID := c.globalNodeID("identity", roleName)
	for _, node := range batch.Nodes {
		bucket, ok := s3BucketName(node)
		if !ok {
			continue
		}
		granted := false
		for _, doc := range docs {
			ok, err := policyGrantsS3Bucket(doc, bucket)
			if err != nil {
				return fmt.Errorf("parse policy for role %s: %w", roleName, err)
			}
			if ok {
				granted = true
				break
			}
		}
		if !granted {
			continue
		}
		addEdge(batch, graph.Edge{
			ID:       c.edgeID(roleID, node.ID, graph.EdgeCanAccess),
			SourceID: roleID,
			TargetID: node.ID,
			Type:     graph.EdgeCanAccess,
			Properties: graph.MustProperties(map[string]any{
				"reason": fmt.Sprintf("Role %s policy allows S3 actions on %s.", roleName, bucket),
			}),
		})
	}
	return nil
}

func s3BucketName(node graph.Node) (string, bool) {
	if node.Type != graph.NodeDatastore || node.Properties == nil || node.Name == "" {
		return "", false
	}
	service, _ := node.Properties["service"].(string)
	if service != "s3" {
		return "", false
	}
	return node.Name, true
}

func addEdge(batch *graph.Batch, edge graph.Edge) {
	for _, existing := range batch.Edges {
		if existing.ID == edge.ID {
			return
		}
	}
	batch.Edges = append(batch.Edges, edge)
}

func instanceProfileName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return ""
}
