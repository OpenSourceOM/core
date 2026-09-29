// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/enrichment/nvd"
)

// FindingCVE is one CVE that matched a workload's inventory.
type FindingCVE struct {
	ID          string
	Title       string
	Description string
	CVSSScore   float64
	Severity    string
	Normalized  int
	Matched     string
}

// Source looks up CVEs for one workload's inventory.
// cveIDs limits the set when non-empty. A CVE that does not match inventory
// is omitted. An empty inventory yields no CVEs.
type Source interface {
	Match(ctx context.Context, inv Inventory, cveIDs []string) ([]FindingCVE, error)
}

func selectCVEs(inv Inventory, cves []nvd.CVE) []FindingCVE {
	var out []FindingCVE
	seen := map[string]struct{}{}
	for _, cve := range cves {
		if _, ok := seen[cve.ID]; ok {
			continue
		}
		matched := matchCPE(inv, cve.Matches)
		if matched == "" {
			continue
		}
		seen[cve.ID] = struct{}{}
		out = append(out, FindingCVE{
			ID:          cve.ID,
			Title:       cve.Title,
			Description: cve.Description,
			CVSSScore:   cve.CVSSScore,
			Severity:    cve.Severity,
			Normalized:  cve.Normalized,
			Matched:     matched,
		})
	}
	return out
}

func matchCPE(inv Inventory, matches []nvd.CPEMatch) string {
	for _, pkg := range inv.Packages {
		if pkg.Kind != kindCPE {
			continue
		}
		for _, m := range matches {
			if cpeApplies(pkg, m) {
				return pkg.Raw
			}
		}
	}
	return ""
}

func cpeApplies(pkg Package, m nvd.CPEMatch) bool {
	if !concreteEqual(m.Part, pkg.Part) || !concreteEqual(m.Vendor, pkg.Vendor) || !concreteEqual(m.Product, pkg.Product) {
		return false
	}
	return versionCovers(pkg.Version, m.Version, m.VersionStartIncluding, m.VersionStartExcluding, m.VersionEndIncluding, m.VersionEndExcluding)
}

type nvdSource struct {
	client *nvd.Client
}

func (s nvdSource) Match(ctx context.Context, inv Inventory, cveIDs []string) ([]FindingCVE, error) {
	if !inv.HasCPE() {
		return nil, nil
	}
	if len(cveIDs) > 0 {
		found := make([]nvd.CVE, 0, len(cveIDs))
		for _, id := range cveIDs {
			cve, err := s.client.Lookup(ctx, id)
			if err != nil {
				return nil, err
			}
			found = append(found, cve)
		}
		return selectCVEs(inv, found), nil
	}

	seen := map[string]struct{}{}
	var found []nvd.CVE
	for _, pkg := range inv.Packages {
		if pkg.Kind != kindCPE || !concreteVersion(pkg.Version) {
			continue
		}
		cves, err := s.client.SearchCPE(ctx, pkg.Raw)
		if err != nil {
			return nil, err
		}
		for _, cve := range cves {
			if _, ok := seen[cve.ID]; ok {
				continue
			}
			seen[cve.ID] = struct{}{}
			found = append(found, cve)
		}
	}
	return selectCVEs(inv, found), nil
}

func normalizeCVEIDs(ids []string) ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if !strings.HasPrefix(id, "CVE-") {
			return nil, fmt.Errorf("cve id %q must start with CVE-", id)
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}
