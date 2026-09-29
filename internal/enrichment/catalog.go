// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/OpenSourceOM/core/internal/enrichment/nvd"
	"github.com/OpenSourceOM/core/internal/enrichment/severity"
)

// OpenSource uses a JSON catalog when catalogPath is set, and NVD otherwise.
// The catalog is the whole source: CPE, package URL, and image matches do not
// also call NVD.
func OpenSource(nvdAPIKey, catalogPath string) (Source, error) {
	if strings.TrimSpace(catalogPath) != "" {
		return loadCatalog(catalogPath)
	}
	return nvdSource{client: nvd.NewClient(nvdAPIKey)}, nil
}

type catalogSource struct {
	records []catalogCVE
	byID    map[string]catalogCVE
}

type catalogFile struct {
	CVEs []catalogCVE `json:"cves"`
}

type catalogCVE struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	CVSSScore   float64          `json:"cvss_score"`
	Severity    string           `json:"severity"`
	Packages    []catalogPackage `json:"packages"`
	Images      []string         `json:"images"`
}

type catalogPackage struct {
	CPE                   string `json:"cpe"`
	Ecosystem             string `json:"ecosystem"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	Version               string `json:"version"`
	VersionStartIncluding string `json:"version_start_including"`
	VersionStartExcluding string `json:"version_start_excluding"`
	VersionEndIncluding   string `json:"version_end_including"`
	VersionEndExcluding   string `json:"version_end_excluding"`
}

func loadCatalog(path string) (catalogSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return catalogSource{}, fmt.Errorf("read cve catalog: %w", err)
	}
	var file catalogFile
	if err := json.Unmarshal(data, &file); err != nil {
		return catalogSource{}, fmt.Errorf("parse cve catalog: %w", err)
	}
	if len(file.CVEs) == 0 {
		return catalogSource{}, fmt.Errorf("cve catalog %s has no cves", path)
	}
	src := catalogSource{byID: map[string]catalogCVE{}}
	for i, rec := range file.CVEs {
		rec.ID = strings.ToUpper(strings.TrimSpace(rec.ID))
		if !strings.HasPrefix(rec.ID, "CVE-") {
			return catalogSource{}, fmt.Errorf("cve catalog entry %d has id %q", i, rec.ID)
		}
		if _, ok := src.byID[rec.ID]; ok {
			return catalogSource{}, fmt.Errorf("cve catalog lists %s more than once", rec.ID)
		}
		if rec.CVSSScore < 0 || rec.CVSSScore > 10 {
			return catalogSource{}, fmt.Errorf("cve catalog %s has cvss_score %v", rec.ID, rec.CVSSScore)
		}
		if len(rec.Packages) == 0 && len(rec.Images) == 0 {
			return catalogSource{}, fmt.Errorf("cve catalog %s has no packages or images", rec.ID)
		}
		for j, pkg := range rec.Packages {
			if err := validateCatalogPackage(rec.ID, j, pkg); err != nil {
				return catalogSource{}, err
			}
		}
		var images []string
		for _, image := range rec.Images {
			image = strings.TrimSpace(image)
			if image == "" {
				return catalogSource{}, fmt.Errorf("cve catalog %s has an empty image", rec.ID)
			}
			images = append(images, image)
		}
		rec.Images = images
		src.byID[rec.ID] = rec
		src.records = append(src.records, rec)
	}
	return src, nil
}

func validateCatalogPackage(id string, index int, pkg catalogPackage) error {
	hasCPE := strings.TrimSpace(pkg.CPE) != ""
	hasPURL := strings.TrimSpace(pkg.Ecosystem) != "" || strings.TrimSpace(pkg.Name) != "" || strings.TrimSpace(pkg.Namespace) != ""
	if hasCPE == hasPURL {
		return fmt.Errorf("cve catalog %s package %d must set cpe or ecosystem and name", id, index)
	}
	bounded := hasBound(pkg.Version, pkg.VersionStartIncluding, pkg.VersionStartExcluding, pkg.VersionEndIncluding, pkg.VersionEndExcluding)
	if hasCPE {
		parsed, ok := parseCPE(strings.TrimSpace(pkg.CPE))
		if !ok {
			return fmt.Errorf("cve catalog %s package %d has invalid cpe %q", id, index, pkg.CPE)
		}
		if !concreteVersion(parsed.Version) && !bounded {
			return fmt.Errorf("cve catalog %s package %d is an unbounded cpe", id, index)
		}
		return nil
	}
	if strings.TrimSpace(pkg.Ecosystem) == "" || strings.TrimSpace(pkg.Name) == "" {
		return fmt.Errorf("cve catalog %s package %d needs ecosystem and name", id, index)
	}
	if !bounded {
		return fmt.Errorf("cve catalog %s package %d has no version bound", id, index)
	}
	return nil
}

func (s catalogSource) Match(_ context.Context, inv Inventory, cveIDs []string) ([]FindingCVE, error) {
	ids, err := normalizeCVEIDs(cveIDs)
	if err != nil {
		return nil, err
	}
	wanted := map[string]struct{}{}
	for _, id := range ids {
		if _, ok := s.byID[id]; !ok {
			return nil, fmt.Errorf("cve %s is not in the catalog", id)
		}
		wanted[id] = struct{}{}
	}
	var out []FindingCVE
	for _, rec := range s.records {
		if len(wanted) > 0 {
			if _, ok := wanted[rec.ID]; !ok {
				continue
			}
		}
		matched, ok := rec.match(inv)
		if !ok {
			continue
		}
		out = append(out, rec.finding(matched))
	}
	return out, nil
}

func (rec catalogCVE) match(inv Inventory) (string, bool) {
	for _, pkg := range inv.Packages {
		for _, spec := range rec.Packages {
			if catalogPackageMatches(pkg, spec) {
				return pkg.Raw, true
			}
		}
	}
	for _, image := range inv.Images {
		for _, want := range rec.Images {
			if image == want {
				return image, true
			}
		}
	}
	return "", false
}

func catalogPackageMatches(pkg Package, spec catalogPackage) bool {
	if strings.TrimSpace(spec.CPE) != "" {
		if pkg.Kind != kindCPE {
			return false
		}
		parsed, ok := parseCPE(strings.TrimSpace(spec.CPE))
		if !ok {
			return false
		}
		if !concreteEqual(parsed.Part, pkg.Part) || !concreteEqual(parsed.Vendor, pkg.Vendor) || !concreteEqual(parsed.Product, pkg.Product) {
			return false
		}
		exact := parsed.Version
		if concreteVersion(spec.Version) {
			exact = spec.Version
		}
		return versionCovers(
			pkg.Version,
			exact,
			spec.VersionStartIncluding,
			spec.VersionStartExcluding,
			spec.VersionEndIncluding,
			spec.VersionEndExcluding,
		)
	}
	if pkg.Kind != kindPURL {
		return false
	}
	if !strings.EqualFold(pkg.Ecosystem, strings.TrimSpace(spec.Ecosystem)) {
		return false
	}
	if !strings.EqualFold(pkg.Namespace, strings.TrimSpace(spec.Namespace)) {
		return false
	}
	if !strings.EqualFold(pkg.Name, strings.TrimSpace(spec.Name)) {
		return false
	}
	return versionCovers(pkg.Version, spec.Version, spec.VersionStartIncluding, spec.VersionStartExcluding, spec.VersionEndIncluding, spec.VersionEndExcluding)
}

func (rec catalogCVE) finding(matched string) FindingCVE {
	level := severity.LevelInfo
	normalized := severity.NormalizedScore(level)
	if rec.CVSSScore > 0 {
		level, normalized = severity.FromCVSS(rec.CVSSScore)
	} else if strings.TrimSpace(rec.Severity) != "" {
		level = severity.FromLabel(rec.Severity)
		normalized = severity.NormalizedScore(level)
	}
	title := strings.TrimSpace(rec.Title)
	if title == "" {
		title = truncateDescription(rec.Description, 120)
	}
	if title == "" {
		title = rec.ID
	}
	return FindingCVE{
		ID:          rec.ID,
		Title:       title,
		Description: rec.Description,
		CVSSScore:   rec.CVSSScore,
		Severity:    level,
		Normalized:  normalized,
		Matched:     matched,
	}
}

func truncateDescription(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
