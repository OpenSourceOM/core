// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package demo

import "github.com/OpenSourceOM/core/internal/graph"

const (
	AccountID    = "111122223333"
	K8sAccountID = "cluster-demo"
	Region       = "us-east-1"

	SecurityGroupWebID = "aws:sg:sg-web"
	WebInstanceID      = "aws:ec2:i-web-1"
	WorkerInstanceID   = "aws:ec2:i-worker-1"
	ProdDBID           = "aws:rds:prod-db"
	PublicLogsID       = "aws:s3:acme-logs-public"
	PrivateAssetsID    = "aws:s3:acme-assets"
	AdminRoleID        = "aws:iam:role/AdminRole"
	AppRoleID          = "aws:iam:role/AppRole"
	K8sFrontendID      = "k8s:svc:prod/frontend"
)

// AccountIDs are the sample accounts om scan demo replaces on each run.
func AccountIDs() []string {
	return []string{AccountID, K8sAccountID}
}

// Collect returns a fixed sample environment. The attack path is
// Internet → sg-web → web-1 → AdminRole → prod-db, and each hop has a reason.
// worker-1 is private and only reaches the private bucket acme-assets.
// No cloud credentials required.
func Collect() graph.Batch {
	p := graph.MustProperties
	edge := func(src, dst, typ, reason string) graph.Edge {
		return graph.Edge{
			ID:         src + "|" + dst + "|" + typ,
			SourceID:   src,
			TargetID:   dst,
			Type:       typ,
			Properties: p(map[string]any{"reason": reason}),
		}
	}

	internet := graph.InternetNodeID
	sgWeb := SecurityGroupWebID
	web := WebInstanceID
	worker := WorkerInstanceID
	db := ProdDBID
	logs := PublicLogsID
	assets := PrivateAssetsID
	admin := AdminRoleID
	app := AppRoleID
	k8s := K8sFrontendID

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
					"instance_type":     "t3.small",
					"imdsv2":            false,
					"public_ip":         true,
					"public_ip_address": "203.0.113.21",
					"instance_profile":  "web-1-profile",
					"security_group":    "sg-web",
				}),
			},
			{
				ID: worker, Type: graph.NodeWorkload, Name: "worker-1", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"instance_type":    "t3.medium",
					"imdsv2":           true,
					"public_ip":        false,
					"instance_profile": "worker-profile",
					"security_group":   "sg-worker",
				}),
			},
			{
				ID: db, Type: graph.NodeDatastore, Name: "prod-db", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"engine":                 "postgres",
					"public_access":          false,
					"encryption":             true,
					"public_access_block":    "n/a",
					"ingress_security_group": "sg-web",
					"ingress_port":           5432,
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
					"admin_access": true,
					"policy":       "AdministratorAccess",
				}),
			},
			{
				ID: app, Type: graph.NodeIdentity, Name: "AppRole", Provider: "aws",
				Region: Region, AccountID: AccountID,
				Properties: p(map[string]any{
					"admin_access": false,
					"policy":       "s3:GetObject on acme-assets",
				}),
			},
			{
				ID: k8s, Type: graph.NodeWorkload, Name: "frontend", Provider: "kubernetes",
				Region: "prod", AccountID: K8sAccountID,
				Properties: p(map[string]any{
					"k8s_kind":         "Service",
					"k8s_service_type": "LoadBalancer",
				}),
			},
		},
		Edges: []graph.Edge{
			edge(internet, sgWeb, graph.EdgeReachable,
				"Security group sg-web allows tcp/443 from 0.0.0.0/0."),
			edge(sgWeb, web, graph.EdgeReachable,
				"web-1 has public IPv4 203.0.113.21 and uses security group sg-web."),
			edge(web, admin, graph.EdgeAssumes,
				"Instance profile web-1-profile attaches role AdminRole."),
			edge(admin, db, graph.EdgeCanAccess,
				"Role policy AdministratorAccess allows rds:*. prod-db is private and allows tcp/5432 from sg-web."),
			edge(internet, logs, graph.EdgeReachable,
				"Bucket policy allows s3:GetObject for Principal * and S3 Block Public Access is disabled. This bucket is not reached through web-1."),
			edge(internet, k8s, graph.EdgeReachable,
				"Service frontend is type LoadBalancer with a public address and has no route to prod-db."),
			edge(worker, app, graph.EdgeAssumes,
				"Instance profile worker-profile attaches role AppRole. worker-1 has no public IP."),
			edge(app, assets, graph.EdgeCanAccess,
				"Role policy allows s3:GetObject on acme-assets only. S3 Block Public Access is enabled."),
		},
	}
}
