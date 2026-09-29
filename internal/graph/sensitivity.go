// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import "strings"

// SensitivityProperty is the datastore mark that distinguishes a crown jewel
// from an unmarked store. Any non-empty value counts as set. The value is
// not interpreted: collectors copy it, they do not classify object contents.
const SensitivityProperty = "sensitivity"

// SensitivityFromTags copies a crown-jewel mark from resource tags or labels.
// The key sensitivity wins over data-class. Matching is case-insensitive.
// A blank value is ignored. The returned string is the tag value, trimmed.
func SensitivityFromTags(tags map[string]string) (string, bool) {
	var sensitivity, dataClass string
	var sensitivityExact, dataClassExact bool
	for key, value := range tags {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(key))
		exact := strings.TrimSpace(key) == name
		switch name {
		case "sensitivity":
			if sensitivity == "" || (exact && !sensitivityExact) {
				sensitivity = value
				sensitivityExact = exact
			}
		case "data-class":
			if dataClass == "" || (exact && !dataClassExact) {
				dataClass = value
				dataClassExact = exact
			}
		}
	}
	if sensitivity != "" {
		return sensitivity, true
	}
	if dataClass != "" {
		return dataClass, true
	}
	return "", false
}

// SetSensitivity writes SensitivityProperty when tags carry a mark.
// An unmarked store is left without the key.
func SetSensitivity(props map[string]any, tags map[string]string) {
	if props == nil {
		return
	}
	value, ok := SensitivityFromTags(tags)
	if !ok {
		return
	}
	props[SensitivityProperty] = value
}
