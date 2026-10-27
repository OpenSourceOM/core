// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"sort"
	"strings"
)

// UnionPackages returns the sorted unique combination of existing and added.
// An identifier that is only in existing stays. That is how a package installed
// on one instance after boot is kept off the shared boot image.
func UnionPackages(existing, added []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, id := range append(append([]string{}, existing...), added...) {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func packageList(v any) []string {
	switch items := v.(type) {
	case []string:
		return items
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
