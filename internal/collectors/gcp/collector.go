// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/OpenSourceOM/core/internal/graph"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
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

	if err := c.collectInstances(ctx, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectStorage(ctx, &batch); err != nil {
		return graph.Batch{}, err
	}
	if err := c.collectServiceAccounts(ctx, &batch); err != nil {
		return graph.Batch{}, err
	}

	c.linkInternetWorkloadsToPublicDatastores(&batch)
	return batch, nil
}

func (c *Collector) collectInstances(ctx context.Context, batch *graph.Batch) error {
	service, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		return fmt.Errorf("compute client: %w", err)
	}

	resp, err := service.Instances.AggregatedList(c.ProjectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("list instances: %w", err)
	}

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
		}
	}
	return nil
}

func (c *Collector) collectStorage(ctx context.Context, batch *graph.Batch) error {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	it := client.Buckets(ctx, c.ProjectID)
	for {
		bucketAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("list buckets: %w", err)
		}

		publicAccess := bucketAttrs.PublicAccessPrevention != storage.PublicAccessPreventionEnforced
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
	return nil
}

func (c *Collector) collectServiceAccounts(ctx context.Context, batch *graph.Batch) error {
	service, err := iam.NewService(ctx)
	if err != nil {
		return fmt.Errorf("iam client: %w", err)
	}

	name := fmt.Sprintf("projects/%s", c.ProjectID)
	resp, err := service.Projects.ServiceAccounts.List(name).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("list service accounts: %w", err)
	}

	for _, sa := range resp.Accounts {
		identityID := c.nodeID(c.Region, "identity", sa.UniqueId)
		adminAccess := strings.Contains(strings.ToLower(sa.DisplayName+" "+sa.Email), "admin")
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        identityID,
			Type:      graph.NodeIdentity,
			Name:      sa.Email,
			Provider:  "gcp",
			Region:    c.Region,
			AccountID: c.ProjectID,
			Properties: graph.MustProperties(map[string]any{
				"email":        sa.Email,
				"admin_access": adminAccess,
			}),
		})
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
		if node.Type != graph.NodeIdentity {
			continue
		}
		admin, _ := node.Properties["admin_access"].(bool)
		if !admin {
			continue
		}
		for _, datastore := range publicDatastores {
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(node.ID, datastore.ID, graph.EdgeCanAccess),
				SourceID: node.ID,
				TargetID: datastore.ID,
				Type:     graph.EdgeCanAccess,
			})
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
			})
		}
	}
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
