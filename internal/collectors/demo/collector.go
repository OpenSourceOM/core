// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package demo

import "github.com/OpenSourceOM/core/internal/graph"

const (
	AccountID = "111122223333"
	Region    = "us-east-1"
)

// Collect returns a fixed sample environment: internet-exposed web tier,
// a production database, public and private buckets, admin vs app identities,
// and a public Kubernetes service. No cloud credentials required.
func Collect() graph.Batch {
	p := graph.MustProperties
	edge := func(src, dst, typ string) graph.Edge {
		return graph.Edge{
			ID:       src + "|" + dst + "|" + typ,
			SourceID: src,
			TargetID: dst,
			Type:     typ,
		}
	}

	internet := graph.InternetNodeID
	sgWeb := "aws:sg:sg-web"
	web := "aws:ec2:i-web-1"
	worker := "aws:ec2:i-worker-1"
	db := "aws:rds:prod-db"
	logs := "aws:s3:acme-logs-public"
	assets := "aws:s3:acme-assets"
	admin := "aws:iam:role/AdminRole"
	app := "aws:iam:role/AppRole"
	k8s := "k8s:svc:prod/frontend"

	return graph.Batch{
		Nodes: []graph.Node{
			{ID: internet, Type: graph.NodeInternet, Name: "Internet", Provider: "demo"},
			{
				ID: sgWeb, Type: graph.NodeNetwork, Name: "sg-web", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"open_ingress": true,
					"cidr":         "0.0.0.0/0",
					"from_port":    443,
				}),
			},
			{
				ID: web, Type: graph.NodeWorkload, Name: "web-1", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"instance_type": "t3.small",
					"imdsv2":        false,
					"public_ip":     true,
				}),
			},
			{
				ID: worker, Type: graph.NodeWorkload, Name: "worker-1", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"instance_type": "t3.medium",
					"imdsv2":        true,
					"public_ip":     false,
				}),
			},
			{
				ID: db, Type: graph.NodeDatastore, Name: "prod-db", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"engine":              "postgres",
					"public_access":       false,
					"encryption":          true,
					"public_access_block": "n/a",
				}),
			},
			{
				ID: logs, Type: graph.NodeDatastore, Name: "acme-logs-public", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"service":             "s3",
					"public_access":       true,
					"public_access_block": "disabled",
					"encryption":          false,
					"versioning":          false,
				}),
			},
			{
				ID: assets, Type: graph.NodeDatastore, Name: "acme-assets", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"service":             "s3",
					"public_access":       false,
					"public_access_block": "enabled",
					"encryption":          true,
					"versioning":          true,
				}),
			},
			{
				ID: admin, Type: graph.NodeIdentity, Name: "AdminRole", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"admin_access":        true,
					"mfa":                 false,
					"unused_access_keys":  true,
				}),
			},
			{
				ID: app, Type: graph.NodeIdentity, Name: "AppRole", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"admin_access":       false,
					"mfa":                true,
					"unused_access_keys": false,
				}),
			},
			{
				ID: k8s, Type: graph.NodeWorkload, Name: "frontend", Provider: "kubernetes",
				Region: "prod", AccountID: "cluster-demo",
				Properties: p(map[string]any{
					"k8s_kind":         "Service",
					"k8s_service_type": "LoadBalancer",
					"public_ip":        true,
				}),
			},
		},
		Edges: []graph.Edge{
			edge(internet, sgWeb, graph.EdgeReachable),
			edge(internet, web, graph.EdgeReachable),
			edge(internet, k8s, graph.EdgeReachable),
			edge(sgWeb, web, graph.EdgeReachable),
			edge(web, db, graph.EdgeReachable),
			edge(web, db, graph.EdgeCanAccess),
			edge(admin, logs, graph.EdgeCanAccess),
			edge(admin, db, graph.EdgeCanAccess),
			edge(app, assets, graph.EdgeCanAccess),
			edge(admin, web, graph.EdgeAssumes),
		},
	}
}
