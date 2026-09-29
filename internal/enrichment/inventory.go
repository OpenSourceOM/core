// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"strconv"
	"strings"
)

const (
	kindCPE  = "cpe"
	kindPURL = "purl"
)

// Package is one identifier a collector stored on a workload.
// CPE 2.3 names are what NVD matches. Package URLs are what a catalog matches.
type Package struct {
	Raw       string
	Kind      string
	Part      string
	Vendor    string
	Product   string
	Version   string
	Ecosystem string
	Namespace string
	Name      string
}

// Inventory is the package and image list on one workload.
type Inventory struct {
	Packages []Package
	Images   []string
}

// ParseInventory reads packages, image, and images from workload properties.
// Entries that are not a CPE 2.3 name or a versioned package URL are skipped.
func ParseInventory(props map[string]any) Inventory {
	if props == nil {
		return Inventory{}
	}
	var inv Inventory
	for _, raw := range stringList(props["packages"]) {
		if pkg, ok := parsePackage(raw); ok {
			inv.Packages = append(inv.Packages, pkg)
		}
	}
	seen := map[string]struct{}{}
	addImage := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		inv.Images = append(inv.Images, ref)
	}
	addImage(stringProp(props["image"]))
	for _, ref := range stringList(props["images"]) {
		addImage(ref)
	}
	return inv
}

func (inv Inventory) HasCPE() bool {
	for _, pkg := range inv.Packages {
		if pkg.Kind == kindCPE && concreteVersion(pkg.Version) {
			return true
		}
	}
	return false
}

func parsePackage(raw string) (Package, bool) {
	raw = strings.TrimSpace(raw)
	if pkg, ok := parseCPE(raw); ok {
		return pkg, true
	}
	return parsePURL(raw)
}

func parseCPE(raw string) (Package, bool) {
	fields := splitCPE(raw)
	if len(fields) < 6 || fields[0] != "cpe" || fields[1] != "2.3" {
		return Package{}, false
	}
	if fields[2] == "" || fields[3] == "" || fields[4] == "" {
		return Package{}, false
	}
	return Package{
		Raw:     raw,
		Kind:    kindCPE,
		Part:    fields[2],
		Vendor:  fields[3],
		Product: fields[4],
		Version: fields[5],
	}, true
}

func parsePURL(raw string) (Package, bool) {
	if !strings.HasPrefix(raw, "pkg:") {
		return Package{}, false
	}
	rest := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	ecosystem, rest, ok := strings.Cut(rest, "/")
	if !ok || ecosystem == "" || rest == "" {
		return Package{}, false
	}
	namespace := ""
	nameVer := rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		namespace = rest[:i]
		nameVer = rest[i+1:]
	}
	name, version, ok := strings.Cut(nameVer, "@")
	if !ok || name == "" || version == "" {
		return Package{}, false
	}
	return Package{
		Raw:       raw,
		Kind:      kindPURL,
		Ecosystem: ecosystem,
		Namespace: namespace,
		Name:      name,
		Version:   version,
	}, true
}

func splitCPE(s string) []string {
	var fields []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			fields = append(fields, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	fields = append(fields, b.String())
	return fields
}

func stringProp(v any) string {
	s, _ := v.(string)
	return s
}

func stringList(v any) []string {
	switch items := v.(type) {
	case string:
		if strings.TrimSpace(items) == "" {
			return nil
		}
		return []string{items}
	case []string:
		return items
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

// versionCovers reports whether version falls in an exact CPE version or a range.
// A wildcard version and an unbounded range do not cover anything.
// Dotted integers compare numerically, so 2.0 and 2.0.0 are equal.
// A version that is not dotted integers matches only an exact string.
func versionCovers(version, exact, startIn, startEx, endIn, endEx string) bool {
	version = strings.TrimSpace(version)
	if !concreteVersion(version) {
		return false
	}
	if hasBound(startIn, startEx, endIn, endEx) {
		return inRange(version, startIn, startEx, endIn, endEx)
	}
	exact = strings.TrimSpace(exact)
	if !concreteVersion(exact) {
		return false
	}
	return versionsEqual(version, exact)
}

func concreteVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "*" && v != "-"
}

func hasBound(parts ...string) bool {
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			return true
		}
	}
	return false
}

func inRange(version, startIn, startEx, endIn, endEx string) bool {
	if strings.TrimSpace(startIn) != "" && !cmpGE(version, startIn) {
		return false
	}
	if strings.TrimSpace(startEx) != "" && !cmpGT(version, startEx) {
		return false
	}
	if strings.TrimSpace(endIn) != "" && !cmpLE(version, endIn) {
		return false
	}
	if strings.TrimSpace(endEx) != "" && !cmpLT(version, endEx) {
		return false
	}
	return true
}

func versionsEqual(a, b string) bool {
	if c, ok := cmpVersion(a, b); ok {
		return c == 0
	}
	return a == b
}

func cmpGE(a, b string) bool {
	c, ok := cmpVersion(a, b)
	return ok && c >= 0
}

func cmpGT(a, b string) bool {
	c, ok := cmpVersion(a, b)
	return ok && c > 0
}

func cmpLE(a, b string) bool {
	c, ok := cmpVersion(a, b)
	return ok && c <= 0
}

func cmpLT(a, b string) bool {
	c, ok := cmpVersion(a, b)
	return ok && c < 0
}

func cmpVersion(a, b string) (int, bool) {
	ap, aok := parseDotted(a)
	bp, bok := parseDotted(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func parseDotted(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func concreteEqual(criteria, value string) bool {
	criteria = strings.ToLower(strings.TrimSpace(criteria))
	value = strings.ToLower(strings.TrimSpace(value))
	if !concreteToken(criteria) || !concreteToken(value) {
		return false
	}
	return criteria == value
}

func concreteToken(v string) bool {
	return v != "" && v != "*" && v != "-"
}
