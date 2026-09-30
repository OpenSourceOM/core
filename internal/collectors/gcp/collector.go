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

	uses, networks, err := c.collectInstances(ctx, &batch)
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
	if err := c.collectCloudSQL(ctx, &batch, networks); err != nil {
		return graph.Batch{}, err
	}
	c.linkGCPAccess(&batch, accounts, uses, bindings)
	// A failed lookup leaves audit_events unset. Inventory still ingests.
	c.attachAuditEvents(ctx, c.auditLogs(ctx), &batch)
	return batch, nil
}

func (c *Collector) collectInstances(ctx context.Context, batch *graph.Batch) ([]gcpInstanceSA, []gcpWorkloadNet, error) {
	service, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		return nil, nil, fmt.Errorf("compute client: %w", err)
	}

	var instances []scopedInstance
	err = service.Instances.AggregatedList(c.ProjectID).Pages(ctx, func(resp *compute.InstanceAggregatedList) error {
		for zonePath, scoped := range resp.Items {
			zone := zoneFromPath(zonePath)
			for _, instance := range scoped.Instances {
				instances = append(instances, scopedInstance{zone: zone, instance: instance})
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list instances: %w", err)
	}

	firewalls, err := listFirewalls(ctx, service, c.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	lbTargets, err := listLoadBalancerTargets(ctx, service, c.ProjectID)
	if err != nil {
		return nil, nil, err
	}

	var uses []gcpInstanceSA
	var networks []gcpWorkloadNet
	seen := map[string]struct{}{}
	for _, item := range instances {
		uses = append(uses, c.recordInstance(batch, item.zone, item.instance, firewalls, lbTargets, seen)...)
		if net, ok := gcpWorkloadNetwork(c, item.zone, item.instance); ok {
			networks = append(networks, net)
		}
	}
	return uses, networks, nil
}

type scopedInstance struct {
	zone     string
	instance *compute.Instance
}

func listFirewalls(ctx context.Context, service *compute.Service, projectID string) ([]*compute.Firewall, error) {
	var firewalls []*compute.Firewall
	err := service.Firewalls.List(projectID).Pages(ctx, func(page *compute.FirewallList) error {
		firewalls = append(firewalls, page.Items...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list firewall rules: %w", err)
	}
	return firewalls, nil
}

func listLoadBalancerTargets(ctx context.Context, service *compute.Service, projectID string) (map[string]string, error) {
	rules, err := listForwardingRules(ctx, service, projectID)
	if err != nil {
		return nil, err
	}
	pools, err := listTargetPools(ctx, service, projectID)
	if err != nil {
		return nil, err
	}
	services, err := listBackendServices(ctx, service, projectID)
	if err != nil {
		return nil, err
	}
	members, err := listInstanceGroupMembers(ctx, service, projectID, externalInstanceGroups(rules, services))
	if err != nil {
		return nil, err
	}
	return gcpLoadBalancerTargets(rules, pools, services, members), nil
}

func listForwardingRules(ctx context.Context, service *compute.Service, projectID string) ([]*compute.ForwardingRule, error) {
	var rules []*compute.ForwardingRule
	err := service.ForwardingRules.AggregatedList(projectID).Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for _, scoped := range page.Items {
			rules = append(rules, scoped.ForwardingRules...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list forwarding rules: %w", err)
	}
	return rules, nil
}

func listTargetPools(ctx context.Context, service *compute.Service, projectID string) ([]*compute.TargetPool, error) {
	var pools []*compute.TargetPool
	err := service.TargetPools.AggregatedList(projectID).Pages(ctx, func(page *compute.TargetPoolAggregatedList) error {
		for _, scoped := range page.Items {
			pools = append(pools, scoped.TargetPools...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list target pools: %w", err)
	}
	return pools, nil
}

func listBackendServices(ctx context.Context, service *compute.Service, projectID string) ([]*compute.BackendService, error) {
	var services []*compute.BackendService
	err := service.BackendServices.AggregatedList(projectID).Pages(ctx, func(page *compute.BackendServiceAggregatedList) error {
		for _, scoped := range page.Items {
			services = append(services, scoped.BackendServices...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list backend services: %w", err)
	}
	return services, nil
}

func listInstanceGroupMembers(ctx context.Context, service *compute.Service, projectID string, groups []string) (map[string][]string, error) {
	members := map[string][]string{}
	for _, groupURL := range groups {
		ref, ok := parseInstanceGroup(groupURL)
		if !ok {
			continue
		}
		project := ref.Project
		if project == "" {
			project = projectID
		}
		var instances []string
		if ref.Regional {
			err := service.RegionInstanceGroups.ListInstances(project, ref.Scope, ref.Name, &compute.RegionInstanceGroupsListInstancesRequest{
				InstanceState: "ALL",
			}).Pages(ctx, func(page *compute.RegionInstanceGroupsListInstances) error {
				for _, item := range page.Items {
					if item != nil && item.Instance != "" {
						instances = append(instances, item.Instance)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("list instances in %s: %w", groupURL, err)
			}
		} else {
			err := service.InstanceGroups.ListInstances(project, ref.Scope, ref.Name, &compute.InstanceGroupsListInstancesRequest{
				InstanceState: "ALL",
			}).Pages(ctx, func(page *compute.InstanceGroupsListInstances) error {
				for _, item := range page.Items {
					if item != nil && item.Instance != "" {
						instances = append(instances, item.Instance)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("list instances in %s: %w", groupURL, err)
			}
		}
		members[groupURL] = instances
		members[ref.Name] = instances
	}
	return members, nil
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
			ID:         datastoreID,
			Type:       graph.NodeDatastore,
			Name:       bucketAttrs.Name,
			Provider:   "gcp",
			Region:     bucketAttrs.Location,
			AccountID:  c.ProjectID,
			Properties: graph.MustProperties(gcsProperties(bucketAttrs.Name, publicAccess, bucketAttrs.Labels)),
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

func gcsProperties(name string, publicAccess bool, labels map[string]string) map[string]any {
	props := map[string]any{
		"resource_id":   name,
		"public_access": publicAccess,
	}
	graph.SetSensitivity(props, labels)
	return props
}
