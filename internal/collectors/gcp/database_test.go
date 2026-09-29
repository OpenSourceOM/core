// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

func TestCloudSQLFollowsNetworkPath(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	web := gcpWorkloadNet{
		ID: c.nodeID("us-central1-a", "workload", "web"), Name: "web",
		NICs: []gcpNIC{{Network: "default", PublicIPs: []string{"203.0.113.21"}}},
	}
	worker := gcpWorkloadNet{
		ID: c.nodeID("us-central1-a", "workload", "worker"), Name: "worker",
		NICs: []gcpNIC{{Network: "default", PrivateIP: "10.0.0.5"}},
	}
	other := gcpWorkloadNet{
		ID: c.nodeID("us-central1-b", "workload", "other"), Name: "other",
		NICs: []gcpNIC{{Network: "isolated", PublicIPs: []string{"198.51.100.8"}}},
	}

	var batch graph.Batch
	c.recordCloudSQL(&batch, &sqladmin.DatabaseInstance{
		Name: "prod", Region: "us-central1", DatabaseVersion: "POSTGRES_15",
		ConnectionName: "proj:us-central1:prod",
		IpAddresses:    []*sqladmin.IpMapping{{Type: "PRIVATE", IpAddress: "10.1.0.3"}},
		Settings: &sqladmin.Settings{
			UserLabels: map[string]string{"data-class": "customer"},
			IpConfiguration: &sqladmin.IpConfiguration{
				Ipv4Enabled:    false,
				PrivateNetwork: "https://www.googleapis.com/compute/v1/projects/proj/global/networks/default",
			},
		},
	}, []gcpWorkloadNet{web, worker, other})
	c.recordCloudSQL(&batch, &sqladmin.DatabaseInstance{
		Name: "open", Region: "us-central1", DatabaseVersion: "MYSQL_8_0",
		ConnectionName: "proj:us-central1:open",
		Settings: &sqladmin.Settings{IpConfiguration: &sqladmin.IpConfiguration{
			Ipv4Enabled: true,
			AuthorizedNetworks: []*sqladmin.AclEntry{
				{Value: "0.0.0.0/0"},
			},
		}},
	}, []gcpWorkloadNet{web, worker, other})
	c.recordCloudSQL(&batch, &sqladmin.DatabaseInstance{
		Name: "office", Region: "europe-west1", DatabaseVersion: "POSTGRES_15",
		ConnectionName: "proj:europe-west1:office",
		Settings: &sqladmin.Settings{IpConfiguration: &sqladmin.IpConfiguration{
			Ipv4Enabled: true,
			AuthorizedNetworks: []*sqladmin.AclEntry{
				{Value: "203.0.113.21/32"},
			},
		}},
	}, []gcpWorkloadNet{web, worker, other})

	prodID := c.nodeID("us-central1", "datastore", "prod")
	openID := c.nodeID("us-central1", "datastore", "open")
	officeID := c.nodeID("europe-west1", "datastore", "office")
	assertPublic := func(id string, want bool) {
		t.Helper()
		node := findNode(batch, id)
		if node.ID == "" {
			t.Fatalf("missing %s", id)
		}
		if node.Properties["service"] != "cloudsql" {
			t.Fatalf("%s service = %v", id, node.Properties["service"])
		}
		if got, _ := node.Properties["public_access"].(bool); got != want {
			t.Fatalf("%s public_access = %v, want %v", node.Name, got, want)
		}
	}
	assertPublic(prodID, false)
	assertPublic(openID, true)
	assertPublic(officeID, false)
	if findNode(batch, prodID).Properties["sensitivity"] != "customer" {
		t.Fatalf("prod sensitivity = %#v", findNode(batch, prodID).Properties["sensitivity"])
	}
	if _, ok := findNode(batch, openID).Properties["sensitivity"]; ok {
		t.Fatal("unlabeled Cloud SQL instance should stay unmarked")
	}

	if !hasEdge(batch, web.ID, prodID, graph.EdgeCanAccess) || !hasEdge(batch, worker.ID, prodID, graph.EdgeCanAccess) {
		t.Fatal("instances on the peered VPC should reach the private Cloud SQL instance")
	}
	if hasEdge(batch, other.ID, prodID, graph.EdgeCanAccess) {
		t.Fatal("an instance on another VPC should not reach the private Cloud SQL instance")
	}
	if !hasEdge(batch, web.ID, openID, graph.EdgeCanAccess) || !hasEdge(batch, other.ID, openID, graph.EdgeCanAccess) {
		t.Fatal("0.0.0.0/0 should allow every instance that has a public IP")
	}
	if hasEdge(batch, worker.ID, openID, graph.EdgeCanAccess) {
		t.Fatal("a private-only instance on another path should not use the public authorized network")
	}
	if !hasEdge(batch, web.ID, officeID, graph.EdgeCanAccess) {
		t.Fatal("web's public IP is an authorized network")
	}
	if hasEdge(batch, other.ID, officeID, graph.EdgeCanAccess) || hasEdge(batch, worker.ID, officeID, graph.EdgeCanAccess) {
		t.Fatal("office should not be reachable from a different address or a private-only instance")
	}
}
