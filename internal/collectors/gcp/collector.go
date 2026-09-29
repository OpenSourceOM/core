// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"github.com/OpenSourceOM/core/internal/graph"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	iamapi "google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type Collector struct {
	ProjectID string
	Region    string
}

func NewCollector(projectID, region string) *Collector {
	return &Collector{
		ProjectID: projectID,
		Region:    region,
	}
}

func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	if c.ProjectID == "" {
		return graph.Batch{}, fmt.Errorf("GCP_PROJECT_ID is required")
	}

	batch := graph.Batch{
		Nodes: []graph.Node{
			{
				ID:       graph.InternetNodeID,
				Type:     graph.NodeInternet,
				Name:     "Internet",
				Provider: "gcp",
			},
		},
	}

	uses, err := c.collectInstances(ctx, &batch)
	if err != nil {
		return graph.Batch{}, err
	}
	bucketBindings, err := c.collectStorage(ctx, &batch)
	if err != nil {
		return graph.Batch{}, err
	}
	accounts, err := c.collectServiceAccounts(ctx)
	if err != nil {
		return graph.Batch{}, err
	}
	projectBindings, err := c.collectProjectIAM(ctx)
	if err != nil {
		return graph.Batch{}, err
	}
	bindings := append(bucketBindings, projectBindings...)
	if err := c.fillCustomRolePermissions(ctx, bindings); err != nil {
		return graph.Batch{}, err
	}
	c.linkGCPAccess(&batch, accounts, uses, bindings)
	return batch, nil
}

func (c *Collector) collectInstances(ctx context.Context, batch *graph.Batch) ([]gcpInstanceSA, error) {
	service, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}

	resp, err := service.Instances.AggregatedList(c.ProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}

	var uses []gcpInstanceSA
	for zonePath, scoped := range resp.Items {
		zone := zoneFromPath(zonePath)
		for _, instance := range scoped.Instances {
			workloadID := c.nodeID(zone, "workload", instance.Name)
			publicIP := ""
			for _, nic := range instance.NetworkInterfaces {
				if nic.AccessConfigs != nil {
					for _, access := range nic.AccessConfigs {
						if access.NatIP != "" {
							publicIP = access.NatIP
						}
					}
				}
			}

			batch.Nodes = append(batch.Nodes, graph.Node{
				ID:        workloadID,
				Type:      graph.NodeWorkload,
				Name:      instance.Name,
				Provider:  "gcp",
				Region:    zone,
				AccountID: c.ProjectID,
				Properties: graph.MustProperties(map[string]any{
					"resource_id": instance.SelfLink,
					"public_ip":   publicIP,
					"status":      instance.Status,
				}),
			})

			if publicIP != "" {
				batch.Edges = append(batch.Edges, graph.Edge{
					ID:       c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
					SourceID: graph.InternetNodeID,
					TargetID: workloadID,
					Type:     graph.EdgeReachable,
				})
			}
			for _, sa := range instance.ServiceAccounts {
				if sa == nil || sa.Email == "" {
					continue
				}
				uses = append(uses, gcpInstanceSA{WorkloadID: workloadID, Email: sa.Email})
			}
		}
	}
	return uses, nil
}

func (c *Collector) collectStorage(ctx context.Context, batch *graph.Batch) ([]gcpBinding, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	var bindings []gcpBinding
	it := client.Buckets(ctx, c.ProjectID)
	for {
		bucketAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}

		publicAccess := false
		policy, err := client.Bucket(bucketAttrs.Name).IAM().Policy(ctx)
		if err == nil {
			publicAccess = gcsPolicyGrantsPublicRead(policy)
			bindings = append(bindings, bindingsFromBucketPolicy(bucketAttrs.Name, policy)...)
		}
		datastoreID := c.nodeID(c.Region, "datastore", bucketAttrs.Name)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        datastoreID,
			Type:      graph.NodeDatastore,
			Name:      bucketAttrs.Name,
			Provider:  "gcp",
			Region:    bucketAttrs.Location,
			AccountID: c.ProjectID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":   bucketAttrs.Name,
				"public_access": publicAccess,
			}),
		})
	}
	return bindings, nil
}

func (c *Collector) collectServiceAccounts(ctx context.Context) ([]gcpPrincipal, error) {
	service, err := iamapi.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam client: %w", err)
	}

	name := fmt.Sprintf("projects/%s", c.ProjectID)
	var accounts []gcpPrincipal
	err = service.Projects.ServiceAccounts.List(name).Pages(ctx, func(resp *iamapi.ListServiceAccountsResponse) error {
		for _, sa := range resp.Accounts {
			if sa == nil || sa.Email == "" {
				continue
			}
			accounts = append(accounts, gcpPrincipal{Email: sa.Email, UniqueID: sa.UniqueId})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	return accounts, nil
}

func (c *Collector) collectProjectIAM(ctx context.Context) ([]gcpBinding, error) {
	service, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resource manager client: %w", err)
	}
	policy, err := service.Projects.GetIamPolicy(c.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get project iam policy: %w", err)
	}
	if policy == nil {
		return nil, nil
	}
	var bindings []gcpBinding
	for _, binding := range policy.Bindings {
		if binding == nil || binding.Role == "" {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, gcpBinding{
				Role:        binding.Role,
				Member:      member,
				Conditional: binding.Condition != nil,
			})
		}
	}
	return bindings, nil
}

func (c *Collector) fillCustomRolePermissions(ctx context.Context, bindings []gcpBinding) error {
	needed := map[string]struct{}{}
	for _, binding := range bindings {
		if gcpCustomRole(binding.Role) {
			needed[binding.Role] = struct{}{}
		}
	}
	if len(needed) == 0 {
		return nil
	}
	service, err := iamapi.NewService(ctx)
	if err != nil {
		return fmt.Errorf("iam client: %w", err)
	}
	perms := map[string][]string{}
	for role := range needed {
		got, err := customRolePermissions(ctx, service, role)
		if err != nil {
			return err
		}
		perms[role] = got
	}
	for i := range bindings {
		if permissions, ok := perms[bindings[i].Role]; ok {
			bindings[i].Permissions = permissions
		}
	}
	return nil
}

func customRolePermissions(ctx context.Context, service *iamapi.Service, role string) ([]string, error) {
	var got *iamapi.Role
	var err error
	switch {
	case strings.HasPrefix(role, "projects/"):
		got, err = service.Projects.Roles.Get(role).Context(ctx).Do()
	case strings.HasPrefix(role, "organizations/"):
		got, err = service.Organizations.Roles.Get(role).Context(ctx).Do()
	default:
		return nil, fmt.Errorf("role %s is not a project or organization custom role", role)
	}
	if err != nil {
		return nil, fmt.Errorf("get role %s: %w", role, err)
	}
	if got == nil {
		return nil, fmt.Errorf("get role %s: empty response", role)
	}
	return got.IncludedPermissions, nil
}

func bindingsFromBucketPolicy(bucket string, policy *iam.Policy) []gcpBinding {
	if policy == nil {
		return nil
	}
	var bindings []gcpBinding
	for _, role := range policy.Roles() {
		for _, member := range policy.Members(role) {
			bindings = append(bindings, gcpBinding{
				Role:   string(role),
				Member: member,
				Bucket: bucket,
			})
		}
	}
	return bindings
}

func (c *Collector) nodeID(region, kind, resource string) string {
	return fmt.Sprintf("gcp:%s:%s:%s:%s", c.ProjectID, region, kind, resource)
}

func (c *Collector) edgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, edgeType)
}

func zoneFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "unknown"
	}
	return parts[len(parts)-1]
}
