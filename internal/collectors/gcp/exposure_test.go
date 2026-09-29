// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"testing"

	"github.com/OpenSourceOM/core/internal/graph"
	"google.golang.org/api/compute/v1"
)

func TestGCPPublicIPWithoutAllowIsNotReachable(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	network := "https://www.googleapis.com/compute/v1/projects/proj/global/networks/default"
	web := gceInstance("web", network, "203.0.113.10")
	deny := &compute.Firewall{
		Name:         "deny-all",
		Network:      network,
		Direction:    "INGRESS",
		Priority:     1000,
		SourceRanges: []string{"0.0.0.0/0"},
		Denied:       []*compute.FirewallDenied{{IPProtocol: "all"}},
	}
	allowLater := &compute.Firewall{
		Name:         "allow-ssh",
		Network:      network,
		Direction:    "INGRESS",
		Priority:     2000,
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
	}

	var denied graph.Batch
	c.recordInstance(&denied, "us-central1-a", web, []*compute.Firewall{deny, allowLater}, nil, nil)
	workloadID := c.nodeID("us-central1-a", "workload", "web")
	if hasEdge(denied, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("public IP behind a higher-priority deny-all should not be reachable")
	}
	if findNode(denied, c.nodeID("global", "network", "deny-all")).ID == "" {
		t.Fatal("deny-all should be a network node")
	}
	if !hasEdge(denied, workloadID, c.nodeID("global", "network", "deny-all"), graph.EdgeAffects) {
		t.Fatal("firewall should be attached to the workload")
	}

	var none graph.Batch
	c.recordInstance(&none, "us-central1-a", web, nil, nil, nil)
	if hasEdge(none, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("public IP with no firewall allow should not be reachable")
	}
}

func TestGCPPublicIPWithAllowIsReachable(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	network := "https://www.googleapis.com/compute/v1/projects/proj/global/networks/default"
	web := gceInstance("web", network, "203.0.113.10")
	allow := &compute.Firewall{
		Name:         "allow-web",
		Network:      network,
		Direction:    "INGRESS",
		Priority:     1000,
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80"}}},
	}
	denyLater := &compute.Firewall{
		Name:         "deny-all",
		Network:      network,
		Direction:    "INGRESS",
		Priority:     65534,
		SourceRanges: []string{"0.0.0.0/0"},
		Denied:       []*compute.FirewallDenied{{IPProtocol: "all"}},
	}
	var batch graph.Batch
	c.recordInstance(&batch, "us-central1-a", web, []*compute.Firewall{denyLater, allow}, nil, nil)
	workloadID := c.nodeID("us-central1-a", "workload", "web")
	edge, ok := edgeByType(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable)
	if !ok {
		t.Fatal("public IP with an allow that outranks deny-all should be reachable")
	}
	if edge.Properties["via_firewall"] != "allow-web" || edge.Properties["via_public_ip"] != "203.0.113.10" {
		t.Fatalf("reachable properties = %#v", edge.Properties)
	}
}

func TestGCPPrivateInstanceBehindLoadBalancerIsReachable(t *testing.T) {
	c := NewCollector("proj", "us-central1")
	network := "https://www.googleapis.com/compute/v1/projects/proj/global/networks/default"
	web := gceInstance("web", network, "")
	allow := &compute.Firewall{
		Name:         "allow-web",
		Network:      network,
		Direction:    "INGRESS",
		Priority:     1000,
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80"}}},
	}
	targets := gcpLoadBalancerTargets(
		[]*compute.ForwardingRule{{
			Name:                "web-lb",
			LoadBalancingScheme: "EXTERNAL",
			Target:              "https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1/targetPools/web-pool",
		}},
		[]*compute.TargetPool{{
			Name:      "web-pool",
			Instances: []string{web.SelfLink},
		}},
		nil,
		nil,
	)

	var batch graph.Batch
	c.recordInstance(&batch, "us-central1-a", web, []*compute.Firewall{allow}, targets, nil)
	workloadID := c.nodeID("us-central1-a", "workload", "web")
	edge, ok := edgeByType(batch, graph.InternetNodeID, workloadID, graph.EdgeReachable)
	if !ok {
		t.Fatal("private instance behind an external load balancer and an allow rule should be reachable")
	}
	if edge.Properties["via_firewall"] != "allow-web" || edge.Properties["via_load_balancer"] != "web-lb" {
		t.Fatalf("reachable properties = %#v", edge.Properties)
	}
	if !hasEdge(batch, workloadID, c.nodeID("global", "network", "allow-web"), graph.EdgeAffects) {
		t.Fatal("allow rule should be attached to the workload")
	}

	var closed graph.Batch
	c.recordInstance(&closed, "us-central1-a", web, []*compute.Firewall{allow}, nil, nil)
	if hasEdge(closed, graph.InternetNodeID, workloadID, graph.EdgeReachable) {
		t.Fatal("an allow rule alone should not expose a private instance")
	}
}

func TestGCPInstanceGroupLoadBalancerTargetsInstance(t *testing.T) {
	group := "https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/instanceGroups/web"
	instance := "https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/instances/web"
	targets := gcpLoadBalancerTargets(
		[]*compute.ForwardingRule{{
			Name:                "web-https",
			LoadBalancingScheme: "EXTERNAL_MANAGED",
			BackendService:      "https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/web",
		}},
		nil,
		[]*compute.BackendService{{
			Name:     "web",
			Backends: []*compute.Backend{{Group: group}},
		}},
		map[string][]string{group: {instance}},
	)
	if targets[instance] != "web-https" {
		t.Fatalf("instance target = %q", targets[instance])
	}
	internal := gcpLoadBalancerTargets(
		[]*compute.ForwardingRule{{
			Name:                "web-internal",
			LoadBalancingScheme: "INTERNAL",
			BackendService:      "https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1/backendServices/web",
		}},
		nil,
		[]*compute.BackendService{{
			Name:     "web",
			Backends: []*compute.Backend{{Group: group}},
		}},
		map[string][]string{group: {instance}},
	)
	if _, ok := internal[instance]; ok {
		t.Fatal("internal forwarding rule should not expose the instance")
	}
}

func gceInstance(name, network, publicIP string) *compute.Instance {
	nic := &compute.NetworkInterface{Network: network}
	if publicIP != "" {
		nic.AccessConfigs = []*compute.AccessConfig{{NatIP: publicIP}}
	}
	return &compute.Instance{
		Name:              name,
		SelfLink:          "https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/instances/" + name,
		NetworkInterfaces: []*compute.NetworkInterface{nic},
	}
}

func edgeByType(batch graph.Batch, source, target, edgeType string) (graph.Edge, bool) {
	for _, edge := range batch.Edges {
		if edge.SourceID == source && edge.TargetID == target && edge.Type == edgeType {
			return edge, true
		}
	}
	return graph.Edge{}, false
}
