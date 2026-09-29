// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
	"github.com/OpenSourceOM/core/internal/graph"
)

type azureNetworkAPI interface {
	getNIC(ctx context.Context, resourceGroup, name string) (armnetwork.Interface, error)
	getPublicIP(ctx context.Context, resourceGroup, name string) (armnetwork.PublicIPAddress, error)
}

type armNetworkAPI struct {
	nics *armnetwork.InterfacesClient
	pips *armnetwork.PublicIPAddressesClient
}

func (a armNetworkAPI) getNIC(ctx context.Context, resourceGroup, name string) (armnetwork.Interface, error) {
	resp, err := a.nics.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return armnetwork.Interface{}, err
	}
	return resp.Interface, nil
}

func (a armNetworkAPI) getPublicIP(ctx context.Context, resourceGroup, name string) (armnetwork.PublicIPAddress, error) {
	resp, err := a.pips.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return armnetwork.PublicIPAddress{}, err
	}
	return resp.PublicIPAddress, nil
}

func vmPublicIP(ctx context.Context, api azureNetworkAPI, vm *armcompute.VirtualMachine) (string, error) {
	if vm == nil || vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return "", nil
	}
	for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if nicRef == nil || nicRef.ID == nil || *nicRef.ID == "" {
			continue
		}
		resourceGroup, name, ok := azureResourceParts(*nicRef.ID)
		if !ok {
			return "", fmt.Errorf("network interface id %s: missing resource group or name", *nicRef.ID)
		}
		nic, err := api.getNIC(ctx, resourceGroup, name)
		if err != nil {
			if azureNotFound(err) {
				continue
			}
			return "", fmt.Errorf("get network interface %s: %w", name, err)
		}
		ip, err := publicIPFromNIC(ctx, api, nic)
		if err != nil {
			return "", err
		}
		if ip != "" {
			return ip, nil
		}
	}
	return "", nil
}

func publicIPFromNIC(ctx context.Context, api azureNetworkAPI, nic armnetwork.Interface) (string, error) {
	if nic.Properties == nil {
		return "", nil
	}
	for _, cfg := range nic.Properties.IPConfigurations {
		ip, err := publicIPFromConfig(ctx, api, cfg)
		if err != nil {
			return "", err
		}
		if ip != "" {
			return ip, nil
		}
	}
	return "", nil
}

func publicIPFromConfig(ctx context.Context, api azureNetworkAPI, cfg *armnetwork.InterfaceIPConfiguration) (string, error) {
	if cfg == nil || cfg.Properties == nil || cfg.Properties.PublicIPAddress == nil {
		return "", nil
	}
	pip := cfg.Properties.PublicIPAddress
	if pip.Properties != nil && pip.Properties.IPAddress != nil && *pip.Properties.IPAddress != "" {
		return *pip.Properties.IPAddress, nil
	}
	if pip.ID == nil || *pip.ID == "" {
		return "", nil
	}
	resourceGroup, name, ok := azureResourceParts(*pip.ID)
	if !ok {
		return "", fmt.Errorf("public ip id %s: missing resource group or name", *pip.ID)
	}
	addr, err := api.getPublicIP(ctx, resourceGroup, name)
	if err != nil {
		if azureNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("get public ip %s: %w", name, err)
	}
	if addr.Properties != nil && addr.Properties.IPAddress != nil {
		return *addr.Properties.IPAddress, nil
	}
	return "", nil
}

// azureNICFacts is one IP configuration on a VM NIC, plus the NSGs that
// filter it. Empty NSG ids mean that control is not attached.
type azureNICFacts struct {
	PublicIP    string
	NicNSGID    string
	SubnetNSGID string
	IPConfigID  string
}

// attachAzureExposure adds NSG network nodes and a REACHABLE edge when an
// internet path is also allowed. A path is a public IP or a public load
// balancer frontend. With no NSG, Azure's platform default allows the path.
// When both a NIC and a subnet NSG are attached, both must allow.
func (c *Collector) attachAzureExposure(batch *graph.Batch, workloadID string, nics []azureNICFacts, nsgs map[string]*armnetwork.SecurityGroup, lbTargets map[string]string, seen map[string]struct{}) error {
	if seen == nil {
		seen = map[string]struct{}{}
	}
	var (
		reachable bool
		viaNSG    string
		viaLB     string
		viaIP     string
	)
	for _, nic := range nics {
		nicNSG, err := lookupSecurityGroup(nsgs, nic.NicNSGID)
		if err != nil {
			return err
		}
		subnetNSG, err := lookupSecurityGroup(nsgs, nic.SubnetNSGID)
		if err != nil {
			return err
		}
		c.attachNSG(batch, workloadID, nicNSG, seen)
		c.attachNSG(batch, workloadID, subnetNSG, seen)

		allowed, via := azureNICInternetAllowed(nicNSG, subnetNSG)
		lb := lbForConfig(nic.IPConfigID, lbTargets)
		if !allowed || (nic.PublicIP == "" && lb == "") || reachable {
			continue
		}
		reachable = true
		viaNSG = via
		viaLB = lb
		viaIP = nic.PublicIP
	}
	if !reachable {
		return nil
	}
	props := map[string]any{}
	if viaNSG != "" {
		props["via_nsg"] = viaNSG
	}
	if viaLB != "" {
		props["via_load_balancer"] = viaLB
	}
	if viaIP != "" {
		props["via_public_ip"] = viaIP
	}
	batch.Edges = append(batch.Edges, graph.Edge{
		ID:         c.edgeID(graph.InternetNodeID, workloadID, graph.EdgeReachable),
		SourceID:   graph.InternetNodeID,
		TargetID:   workloadID,
		Type:       graph.EdgeReachable,
		Properties: graph.MustProperties(props),
	})
	return nil
}

func (c *Collector) attachNSG(batch *graph.Batch, workloadID string, nsg *armnetwork.SecurityGroup, seen map[string]struct{}) {
	if nsg == nil {
		return
	}
	nodeID := c.nodeID("network", nsgNodeResource(nsg))
	if _, ok := seen[nodeID]; !ok {
		seen[nodeID] = struct{}{}
		location := c.Location
		if nsg.Location != nil && *nsg.Location != "" {
			location = *nsg.Location
		}
		open := nsgAllowsInternet(nsg)
		batch.Nodes = append(batch.Nodes, graph.Node{
			ID:        nodeID,
			Type:      graph.NodeNetwork,
			Name:      securityGroupName(nsg),
			Provider:  "azure",
			Region:    location,
			AccountID: c.SubscriptionID,
			Properties: graph.MustProperties(map[string]any{
				"resource_id":     safeString(nsg.ID),
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

func readVMNetwork(ctx context.Context, api azureNetworkAPI, vm *armcompute.VirtualMachine, subnetNSG map[string]string) ([]azureNICFacts, error) {
	if vm == nil || vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return nil, nil
	}
	var facts []azureNICFacts
	for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if nicRef == nil || nicRef.ID == nil || *nicRef.ID == "" {
			continue
		}
		resourceGroup, name, ok := azureResourceParts(*nicRef.ID)
		if !ok {
			return nil, fmt.Errorf("network interface id %s: missing resource group or name", *nicRef.ID)
		}
		nic, err := api.getNIC(ctx, resourceGroup, name)
		if err != nil {
			if azureNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get network interface %s: %w", name, err)
		}
		nicNSG := ""
		if nic.Properties != nil && nic.Properties.NetworkSecurityGroup != nil && nic.Properties.NetworkSecurityGroup.ID != nil {
			nicNSG = *nic.Properties.NetworkSecurityGroup.ID
		}
		if nic.Properties == nil || len(nic.Properties.IPConfigurations) == 0 {
			facts = append(facts, azureNICFacts{NicNSGID: nicNSG})
			continue
		}
		for _, cfg := range nic.Properties.IPConfigurations {
			if cfg == nil {
				continue
			}
			ip, err := publicIPFromConfig(ctx, api, cfg)
			if err != nil {
				return nil, err
			}
			fact := azureNICFacts{PublicIP: ip, NicNSGID: nicNSG, SubnetNSGID: subnetNSGID(cfg, subnetNSG)}
			if cfg.ID != nil {
				fact.IPConfigID = *cfg.ID
			}
			facts = append(facts, fact)
		}
	}
	return facts, nil
}

func subnetNSGID(cfg *armnetwork.InterfaceIPConfiguration, index map[string]string) string {
	if cfg == nil || cfg.Properties == nil || cfg.Properties.Subnet == nil {
		return ""
	}
	sub := cfg.Properties.Subnet
	if sub.Properties != nil && sub.Properties.NetworkSecurityGroup != nil && sub.Properties.NetworkSecurityGroup.ID != nil && *sub.Properties.NetworkSecurityGroup.ID != "" {
		return *sub.Properties.NetworkSecurityGroup.ID
	}
	if sub.ID == nil || index == nil {
		return ""
	}
	return index[strings.ToLower(*sub.ID)]
}

func indexSecurityGroups(groups []*armnetwork.SecurityGroup) map[string]*armnetwork.SecurityGroup {
	out := map[string]*armnetwork.SecurityGroup{}
	for _, group := range groups {
		if group == nil || group.ID == nil || *group.ID == "" {
			continue
		}
		out[strings.ToLower(*group.ID)] = group
	}
	return out
}

func lookupSecurityGroup(nsgs map[string]*armnetwork.SecurityGroup, id string) (*armnetwork.SecurityGroup, error) {
	if id == "" {
		return nil, nil
	}
	nsg := nsgs[strings.ToLower(id)]
	if nsg == nil {
		return nil, fmt.Errorf("network security group %s was not listed", id)
	}
	return nsg, nil
}

func subnetNSGIndex(vnets []*armnetwork.VirtualNetwork) map[string]string {
	out := map[string]string{}
	for _, vnet := range vnets {
		if vnet == nil || vnet.Properties == nil {
			continue
		}
		for _, subnet := range vnet.Properties.Subnets {
			if subnet == nil || subnet.ID == nil || subnet.Properties == nil || subnet.Properties.NetworkSecurityGroup == nil || subnet.Properties.NetworkSecurityGroup.ID == nil {
				continue
			}
			out[strings.ToLower(*subnet.ID)] = *subnet.Properties.NetworkSecurityGroup.ID
		}
	}
	return out
}

func azurePublicLBTargets(lbs []*armnetwork.LoadBalancer) map[string]string {
	out := map[string]string{}
	for _, lb := range lbs {
		if lb == nil || lb.Name == nil || lb.Properties == nil || !loadBalancerHasPublicFrontend(lb) {
			continue
		}
		for _, pool := range lb.Properties.BackendAddressPools {
			if pool == nil || pool.Properties == nil {
				continue
			}
			for _, cfg := range pool.Properties.BackendIPConfigurations {
				if cfg == nil || cfg.ID == nil || *cfg.ID == "" {
					continue
				}
				id := strings.ToLower(*cfg.ID)
				if _, ok := out[id]; !ok {
					out[id] = *lb.Name
				}
			}
		}
	}
	return out
}

func loadBalancerHasPublicFrontend(lb *armnetwork.LoadBalancer) bool {
	for _, frontend := range lb.Properties.FrontendIPConfigurations {
		if frontend == nil || frontend.Properties == nil || frontend.Properties.PublicIPAddress == nil || frontend.Properties.PublicIPAddress.ID == nil {
			continue
		}
		if *frontend.Properties.PublicIPAddress.ID != "" {
			return true
		}
	}
	return false
}

func lbForConfig(id string, targets map[string]string) string {
	if id == "" || targets == nil {
		return ""
	}
	return targets[strings.ToLower(id)]
}

func azureNICInternetAllowed(nicNSG, subnetNSG *armnetwork.SecurityGroup) (bool, string) {
	if nicNSG == nil && subnetNSG == nil {
		return true, ""
	}
	via := ""
	if nicNSG != nil {
		if !nsgAllowsInternet(nicNSG) {
			return false, ""
		}
		via = securityGroupName(nicNSG)
	}
	if subnetNSG != nil {
		if !nsgAllowsInternet(subnetNSG) {
			return false, ""
		}
		if via == "" {
			via = securityGroupName(subnetNSG)
		}
	}
	return true, via
}

// nsgAllowsInternet reports whether any inbound internet allow survives a
// higher-priority deny. A group with no matching allow is closed, including
// one that only has Azure's default DenyAllInBound rule.
func nsgAllowsInternet(nsg *armnetwork.SecurityGroup) bool {
	var denies []*armnetwork.SecurityRule
	for _, rule := range sortedNSGRules(nsg) {
		if !ruleMatchesInternetIngress(rule) {
			continue
		}
		switch ruleAccess(rule) {
		case armnetwork.SecurityRuleAccessDeny:
			denies = append(denies, rule)
		case armnetwork.SecurityRuleAccessAllow:
			if !azureAllowCovered(rule, denies) {
				return true
			}
		}
	}
	return false
}

func sortedNSGRules(nsg *armnetwork.SecurityGroup) []*armnetwork.SecurityRule {
	if nsg == nil || nsg.Properties == nil {
		return nil
	}
	rules := make([]*armnetwork.SecurityRule, 0, len(nsg.Properties.SecurityRules)+len(nsg.Properties.DefaultSecurityRules))
	rules = append(rules, nsg.Properties.SecurityRules...)
	rules = append(rules, nsg.Properties.DefaultSecurityRules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return nsgRulePriority(rules[i]) < nsgRulePriority(rules[j])
	})
	return rules
}

func nsgRulePriority(rule *armnetwork.SecurityRule) int32 {
	if rule == nil || rule.Properties == nil || rule.Properties.Priority == nil {
		return 1 << 30
	}
	return *rule.Properties.Priority
}

func ruleAccess(rule *armnetwork.SecurityRule) armnetwork.SecurityRuleAccess {
	if rule == nil || rule.Properties == nil || rule.Properties.Access == nil {
		return ""
	}
	return *rule.Properties.Access
}

func ruleMatchesInternetIngress(rule *armnetwork.SecurityRule) bool {
	if rule == nil || rule.Properties == nil || rule.Properties.Direction == nil {
		return false
	}
	if *rule.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
		return false
	}
	var prefixes []string
	if rule.Properties.SourceAddressPrefix != nil {
		prefixes = append(prefixes, *rule.Properties.SourceAddressPrefix)
	}
	for _, prefix := range rule.Properties.SourceAddressPrefixes {
		if prefix != nil {
			prefixes = append(prefixes, *prefix)
		}
	}
	for _, prefix := range prefixes {
		switch strings.ToLower(strings.TrimSpace(prefix)) {
		case "*", "internet", "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

func azureAllowCovered(allow *armnetwork.SecurityRule, denies []*armnetwork.SecurityRule) bool {
	allowAll, allowRanges, ok := azureDestPorts(allow)
	if !ok {
		return true
	}
	allowProto := protocolOf(allow)
	allowPriority := nsgRulePriority(allow)
	if allowAll {
		for _, deny := range denies {
			if nsgRulePriority(deny) > allowPriority || !azureProtoCovers(protocolOf(deny), allowProto) {
				continue
			}
			denyAll, _, denyOK := azureDestPorts(deny)
			if denyOK && denyAll {
				return true
			}
		}
		return false
	}
	var covers [][2]int
	for _, deny := range denies {
		if nsgRulePriority(deny) > allowPriority || !azureProtoCovers(protocolOf(deny), allowProto) {
			continue
		}
		denyAll, denyRanges, denyOK := azureDestPorts(deny)
		if !denyOK {
			continue
		}
		if denyAll {
			return true
		}
		covers = append(covers, denyRanges...)
	}
	if len(allowRanges) == 0 {
		return true
	}
	for _, allowed := range allowRanges {
		if !rangeCovered(allowed, covers) {
			return false
		}
	}
	return true
}

func protocolOf(rule *armnetwork.SecurityRule) armnetwork.SecurityRuleProtocol {
	if rule == nil || rule.Properties == nil || rule.Properties.Protocol == nil {
		return ""
	}
	return *rule.Properties.Protocol
}

func azureProtoCovers(deny, allow armnetwork.SecurityRuleProtocol) bool {
	if deny == armnetwork.SecurityRuleProtocolAsterisk {
		return true
	}
	if allow == armnetwork.SecurityRuleProtocolAsterisk {
		return false
	}
	return deny != "" && strings.EqualFold(string(deny), string(allow))
}

func azureDestPorts(rule *armnetwork.SecurityRule) (bool, [][2]int, bool) {
	if rule == nil || rule.Properties == nil {
		return false, nil, false
	}
	var raw []string
	if rule.Properties.DestinationPortRange != nil {
		raw = append(raw, *rule.Properties.DestinationPortRange)
	}
	for _, port := range rule.Properties.DestinationPortRanges {
		if port != nil {
			raw = append(raw, *port)
		}
	}
	if len(raw) == 0 {
		return false, nil, false
	}
	var ranges [][2]int
	for _, port := range raw {
		port = strings.TrimSpace(port)
		if port == "*" {
			return true, nil, true
		}
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
		return false, nil, false
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

func nsgNodeResource(nsg *armnetwork.SecurityGroup) string {
	if nsg != nil && nsg.ID != nil {
		if group, name, ok := azureResourceParts(*nsg.ID); ok {
			return group + "/" + name
		}
	}
	return securityGroupName(nsg)
}

func securityGroupName(nsg *armnetwork.SecurityGroup) string {
	if nsg != nil && nsg.Name != nil && *nsg.Name != "" {
		return *nsg.Name
	}
	return "nsg"
}

func azureBlobPublic(allow *bool, containers []*armstorage.ListContainerItem) bool {
	if allow != nil && !*allow {
		return false
	}
	for _, item := range containers {
		if item == nil || item.Properties == nil || item.Properties.PublicAccess == nil {
			continue
		}
		switch *item.Properties.PublicAccess {
		case armstorage.PublicAccessBlob, armstorage.PublicAccessContainer:
			return true
		}
	}
	return false
}

func azureResourceGroup(id string) (string, bool) {
	group, _, ok := azureResourceParts(id)
	return group, ok
}

func azureResourceParts(id string) (resourceGroup, name string, ok bool) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	var group string
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			group = parts[i+1]
		}
	}
	if group == "" || len(parts) == 0 {
		return "", "", false
	}
	name = parts[len(parts)-1]
	if name == "" {
		return "", "", false
	}
	return group, name, true
}

func azureNotFound(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}
