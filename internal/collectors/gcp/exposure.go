// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"strconv"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"google.golang.org/api/compute/v1"
)

// recordInstance adds one GCE instance, the firewall rules that apply to it,
// and a REACHABLE edge when an internet path is also allowed by those rules.
// An internet path is a public address or a public load balancer. GCP's
// implicit deny means a public address with no matching allow stays closed.
func (c *Collector) recordInstance(batch *graph.Batch, zone string, instance *compute.Instance, firewalls []*compute.Firewall, lbTargets map[string]string, seen map[string]struct{}) []gcpInstanceSA {
	if instance == nil || instance.Name == "" {
		return nil
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}

	workloadID := c.nodeID(zone, "workload", instance.Name)
	publicIP := instancePublicIP(instance)
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

	for _, fw := range firewalls {
		if firewallApplies(fw, instance) {
			c.attachFirewall(batch, workloadID, fw, seen)
		}
	}

	open, viaFW := firewallExposesInstance(firewalls, instance)
	lb := lbTargetForInstance(instance, lbTargets)
	if (publicIP != "" || lb != "") && open {
		props := map[string]any{}
		if viaFW != "" {
			props["via_firewall"] = viaFW
		}
		if publicIP != "" {
			props["via_public_ip"] = publicIP
		}
		if lb != "" {
			props["via_load_balancer"] = lb
		}
		batch.Edges = append(batch.Edges, graph.Edge{
			ID:         c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
			SourceID:   graph.InternetNodeID,
			TargetID:   workloadID,
			Type:       graph.EdgeReachable,
			Properties: graph.MustProperties(props),
		})
	}

	var uses []gcpInstanceSA
	for _, sa := range instance.ServiceAccounts {
		if sa == nil || sa.Email == "" {
			continue
		}
		uses = append(uses, gcpInstanceSA{WorkloadID: workloadID, Email: sa.Email})
	}
	return uses
}

func (c *Collector) attachFirewall(batch *graph.Batch, workloadID string, fw *compute.Firewall, seen map[string]struct{}) {
	if fw == nil || fw.Name == "" {
		return
	}
	nodeID := c.nodeID("global", "network", fw.Name)
	if _, ok := seen[nodeID]; !ok {
		seen[nodeID] = struct{}{}
		open := firewallRuleAllowsInternet(fw)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        nodeID,
			Type:      graph.NodeNetwork,
			Name:      fw.Name,
			Provider:  "gcp",
			AccountID: c.ProjectID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":     fw.SelfLink,
				"network":         resourceName(fw.Network),
				"priority":        fw.Priority,
				"internet_facing": open,
				"open_ingress":    open,
			}),
		})
	}
	edgeID := c.edgeID(workloadID, nodeID, graph.EdgeAffects)
	if _, ok := seen[edgeID]; ok {
		return
	}
	seen[edgeID] = struct{}{}
	batch.Edges = append(batch.Edges, graph.Edge{
		ID:       edgeID,
		SourceID: workloadID,
		TargetID: nodeID,
		Type:     graph.EdgeAffects,
	})
}

func instancePublicIP(instance *compute.Instance) string {
	if instance == nil {
		return ""
	}
	for _, nic := range instance.NetworkInterfaces {
		if nic == nil {
			continue
		}
		for _, access := range nic.AccessConfigs {
			if access == nil {
				continue
			}
			if access.NatIP != "" {
				return access.NatIP
			}
			if access.ExternalIpv6 != "" {
				return access.ExternalIpv6
			}
		}
		for _, access := range nic.Ipv6AccessConfigs {
			if access != nil && access.ExternalIpv6 != "" {
				return access.ExternalIpv6
			}
		}
	}
	return ""
}

// firewallApplies reports whether an enabled ingress rule selects the instance.
// Empty target tags and service accounts select every instance on the network.
func firewallApplies(fw *compute.Firewall, instance *compute.Instance) bool {
	if fw == nil || instance == nil || fw.Disabled || fw.Name == "" || fw.Direction == "EGRESS" {
		return false
	}
	if !firewallNetworkMatches(fw, instance) {
		return false
	}
	if len(fw.TargetTags) == 0 && len(fw.TargetServiceAccounts) == 0 {
		return true
	}
	return tagOverlap(fw.TargetTags, instance) || serviceAccountOverlap(fw.TargetServiceAccounts, instance)
}

func firewallNetworkMatches(fw *compute.Firewall, instance *compute.Instance) bool {
	want := resourceName(fw.Network)
	if want == "" {
		return false
	}
	for _, nic := range instance.NetworkInterfaces {
		if nic != nil && resourceName(nic.Network) == want {
			return true
		}
	}
	return false
}

func tagOverlap(targets []string, instance *compute.Instance) bool {
	if instance.Tags == nil {
		return false
	}
	have := map[string]struct{}{}
	for _, tag := range instance.Tags.Items {
		have[tag] = struct{}{}
	}
	for _, tag := range targets {
		if _, ok := have[tag]; ok {
			return true
		}
	}
	return false
}

func serviceAccountOverlap(targets []string, instance *compute.Instance) bool {
	have := map[string]struct{}{}
	for _, sa := range instance.ServiceAccounts {
		if sa != nil && sa.Email != "" {
			have[sa.Email] = struct{}{}
		}
	}
	for _, email := range targets {
		if _, ok := have[email]; ok {
			return true
		}
	}
	return false
}

func firewallInternetSource(fw *compute.Firewall) bool {
	for _, cidr := range fw.SourceRanges {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return true
		}
	}
	return false
}

func firewallRuleAllowsInternet(fw *compute.Firewall) bool {
	return fw != nil && !fw.Disabled && fw.Direction != "EGRESS" && firewallInternetSource(fw) && len(fw.Allowed) > 0
}

// firewallExposesInstance reports whether any internet ingress allow survives
// a higher-priority deny. Equal priority follows GCP: deny wins.
func firewallExposesInstance(rules []*compute.Firewall, instance *compute.Instance) (bool, string) {
	var allows, denies []*compute.Firewall
	for _, fw := range rules {
		if !firewallApplies(fw, instance) || !firewallInternetSource(fw) {
			continue
		}
		if len(fw.Allowed) > 0 {
			allows = append(allows, fw)
		}
		if len(fw.Denied) > 0 {
			denies = append(denies, fw)
		}
	}
	var best *compute.Firewall
	for _, allow := range allows {
		if firewallAllowCovered(allow, denies) {
			continue
		}
		if best == nil || allow.Priority < best.Priority {
			best = allow
		}
	}
	if best == nil {
		return false, ""
	}
	return true, best.Name
}

func firewallAllowCovered(allow *compute.Firewall, denies []*compute.Firewall) bool {
	if allow == nil || len(allow.Allowed) == 0 {
		return true
	}
	for _, spec := range allow.Allowed {
		if spec == nil {
			continue
		}
		if !gcpSpecCovered(allow.Priority, spec, denies) {
			return false
		}
	}
	return true
}

func gcpSpecCovered(allowPriority int64, spec *compute.FirewallAllowed, denies []*compute.Firewall) bool {
	for _, deny := range denies {
		if deny == nil || deny.Priority > allowPriority {
			continue
		}
		for _, denied := range deny.Denied {
			if denied == nil {
				continue
			}
			if gcpProtoCovers(denied.IPProtocol, spec.IPProtocol) && gcpPortsCover(denied.Ports, spec.Ports) {
				return true
			}
		}
	}
	return false
}

func gcpProtoCovers(denyProto, allowProto string) bool {
	denyProto = strings.ToLower(denyProto)
	allowProto = strings.ToLower(allowProto)
	if denyProto == "all" {
		return true
	}
	if allowProto == "all" {
		return false
	}
	return denyProto != "" && denyProto == allowProto
}

func gcpPortsCover(denyPorts, allowPorts []string) bool {
	denyAll, denyRanges, denyOK := parsePortList(denyPorts)
	if !denyOK {
		return false
	}
	if denyAll {
		return true
	}
	allowAll, allowRanges, allowOK := parsePortList(allowPorts)
	if !allowOK || allowAll || len(allowRanges) == 0 {
		return false
	}
	for _, allowed := range allowRanges {
		if !rangeCovered(allowed, denyRanges) {
			return false
		}
	}
	return true
}

// parsePortList treats an empty list as every port, which is GCP's meaning
// when a firewall spec omits ports.
func parsePortList(ports []string) (all bool, ranges [][2]int, ok bool) {
	if len(ports) == 0 {
		return true, nil, true
	}
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		lo, hi, parsed := parsePortRange(port)
		if !parsed {
			return false, nil, false
		}
		ranges = append(ranges, [2]int{lo, hi})
	}
	if len(ranges) == 0 {
		return true, nil, true
	}
	return false, ranges, true
}

func parsePortRange(raw string) (int, int, bool) {
	raw = strings.TrimSpace(raw)
	loRaw, hiRaw := raw, raw
	if before, after, found := strings.Cut(raw, "-"); found {
		loRaw, hiRaw = before, after
	}
	lo, errLo := strconv.Atoi(strings.TrimSpace(loRaw))
	hi, errHi := strconv.Atoi(strings.TrimSpace(hiRaw))
	if errLo != nil || errHi != nil || lo < 0 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func rangeCovered(target [2]int, covers [][2]int) bool {
	cur := target[0]
	for cur <= target[1] {
		next := cur
		for _, cover := range covers {
			if cover[0] <= cur && cur <= cover[1] && cover[1]+1 > next {
				next = cover[1] + 1
			}
		}
		if next == cur {
			return false
		}
		cur = next
	}
	return true
}

func lbTargetForInstance(instance *compute.Instance, targets map[string]string) string {
	if instance == nil || len(targets) == 0 {
		return ""
	}
	if name := targets[instance.SelfLink]; name != "" {
		return name
	}
	return targets[instance.Name]
}

// gcpLoadBalancerTargets maps an instance self link or name to the external
// forwarding rule that sends it traffic. Internal schemes are ignored.
// groupMembers is keyed by instance-group URL or name.
func gcpLoadBalancerTargets(rules []*compute.ForwardingRule, pools []*compute.TargetPool, services []*compute.BackendService, groupMembers map[string][]string) map[string]string {
	poolByRef := indexTargetPools(pools)
	serviceByRef := indexBackendServices(services)

	out := map[string]string{}
	add := func(instance, ruleName string) {
		if instance == "" || ruleName == "" {
			return
		}
		if _, ok := out[instance]; !ok {
			out[instance] = ruleName
		}
		if name := resourceName(instance); name != "" {
			if _, ok := out[name]; !ok {
				out[name] = ruleName
			}
		}
	}
	for _, rule := range rules {
		if !forwardingRuleExternal(rule) {
			continue
		}
		if strings.Contains(rule.Target, "/targetPools/") {
			if pool := lookupTargetPool(poolByRef, rule.Target); pool != nil {
				for _, instance := range pool.Instances {
					add(instance, rule.Name)
				}
			}
		}
		if rule.BackendService == "" {
			continue
		}
		service := lookupBackendService(serviceByRef, rule.BackendService)
		if service == nil {
			continue
		}
		for _, backend := range service.Backends {
			if backend == nil {
				continue
			}
			for _, instance := range groupMembersLookup(groupMembers, backend.Group) {
				add(instance, rule.Name)
			}
		}
	}
	return out
}

func forwardingRuleExternal(rule *compute.ForwardingRule) bool {
	if rule == nil || rule.Name == "" {
		return false
	}
	switch strings.ToUpper(rule.LoadBalancingScheme) {
	case "", "EXTERNAL", "EXTERNAL_MANAGED":
		return true
	default:
		return false
	}
}

func groupMembersLookup(groups map[string][]string, groupURL string) []string {
	if groups == nil {
		return nil
	}
	if members, ok := groups[groupURL]; ok {
		return members
	}
	return groups[resourceName(groupURL)]
}

func resourceName(raw string) string {
	parts := urlPath(raw)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func urlPath(raw string) []string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
		if j := strings.Index(raw, "/"); j >= 0 {
			raw = raw[j+1:]
		} else {
			return nil
		}
	}
	raw = strings.Trim(raw, "/")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "/")
}

type instanceGroupRef struct {
	Project  string
	Scope    string
	Regional bool
	Name     string
}

func parseInstanceGroup(raw string) (instanceGroupRef, bool) {
	parts := urlPath(raw)
	var ref instanceGroupRef
	found := false
	for i := 0; i+1 < len(parts); i++ {
		switch parts[i] {
		case "projects":
			ref.Project = parts[i+1]
		case "zones":
			ref.Scope = parts[i+1]
			ref.Regional = false
		case "regions":
			ref.Scope = parts[i+1]
			ref.Regional = true
		case "instanceGroups":
			ref.Name = parts[i+1]
			found = true
		}
	}
	if !found || ref.Name == "" || ref.Scope == "" {
		return instanceGroupRef{}, false
	}
	return ref, true
}

func indexTargetPools(pools []*compute.TargetPool) map[string]*compute.TargetPool {
	out := map[string]*compute.TargetPool{}
	for _, pool := range pools {
		if pool == nil {
			continue
		}
		if pool.SelfLink != "" {
			out[pool.SelfLink] = pool
		}
		if pool.Name != "" {
			if _, ok := out[pool.Name]; !ok {
				out[pool.Name] = pool
			}
		}
	}
	return out
}

func indexBackendServices(services []*compute.BackendService) map[string]*compute.BackendService {
	out := map[string]*compute.BackendService{}
	for _, service := range services {
		if service == nil {
			continue
		}
		if service.SelfLink != "" {
			out[service.SelfLink] = service
		}
		if service.Name != "" {
			if _, ok := out[service.Name]; !ok {
				out[service.Name] = service
			}
		}
	}
	return out
}

func lookupTargetPool(index map[string]*compute.TargetPool, raw string) *compute.TargetPool {
	if index == nil || raw == "" {
		return nil
	}
	if pool := index[raw]; pool != nil {
		return pool
	}
	return index[resourceName(raw)]
}

func lookupBackendService(index map[string]*compute.BackendService, raw string) *compute.BackendService {
	if index == nil || raw == "" {
		return nil
	}
	if service := index[raw]; service != nil {
		return service
	}
	return index[resourceName(raw)]
}

// externalInstanceGroups returns instance-group URLs used by external forwarding rules.
// Network endpoint groups are skipped; this collector does not expand them.
func externalInstanceGroups(rules []*compute.ForwardingRule, services []*compute.BackendService) []string {
	serviceByRef := indexBackendServices(services)
	var groups []string
	seen := map[string]struct{}{}
	for _, rule := range rules {
		if !forwardingRuleExternal(rule) || rule.BackendService == "" {
			continue
		}
		service := lookupBackendService(serviceByRef, rule.BackendService)
		if service == nil {
			continue
		}
		for _, backend := range service.Backends {
			if backend == nil || backend.Group == "" {
				continue
			}
			if _, ok := seen[backend.Group]; ok {
				continue
			}
			if _, ok := parseInstanceGroup(backend.Group); !ok {
				continue
			}
			seen[backend.Group] = struct{}{}
			groups = append(groups, backend.Group)
		}
	}
	return groups
}
