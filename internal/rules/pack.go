// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/OpenSourceOM/core/packs"
	"gopkg.in/yaml.v3"
)

type PackFile struct {
	Pack        string     `yaml:"pack"`
	Version     string     `yaml:"version"`
	Description string     `yaml:"description"`
	Rules       []PackRule `yaml:"rules"`
}

type PackRule struct {
	ID           string    `yaml:"id"`
	Name         string    `yaml:"name"`
	Description  string    `yaml:"description"`
	Framework    string    `yaml:"framework"`
	Control      string    `yaml:"control"`
	ResourceType string    `yaml:"resource_type"`
	BaseScore    int       `yaml:"base_score"`
	Match        PackMatch `yaml:"match"`
}

type PackMatch struct {
	Properties map[string]any `yaml:"properties"`
	Graph      *GraphMatch    `yaml:"graph"`
}

type GraphMatch struct {
	InternetReachable *bool `yaml:"internet_reachable"`
	PathToDatastore   *bool `yaml:"path_to_datastore"`
	AdminCanAccess    *bool `yaml:"admin_can_access"`
}

func LoadEmbeddedPacks() ([]Rule, error) {
	entries, err := fs.Glob(packs.FS, "*.yaml")
	if err != nil {
		return nil, err
	}
	var out []Rule
	for _, name := range entries {
		raw, err := packs.FS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		rules, err := parsePack(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, rules...)
	}
	return out, nil
}

func parsePack(raw []byte) ([]Rule, error) {
	var file PackFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(file.Rules))
	for _, spec := range file.Rules {
		if strings.TrimSpace(spec.ID) == "" || spec.ResourceType == "" {
			return nil, fmt.Errorf("pack %s: rule missing id or resource_type", file.Pack)
		}
		spec := spec
		out = append(out, Rule{
			ID:          spec.ID,
			Name:        spec.Name,
			Description: spec.Description,
			BaseScore:   spec.BaseScore,
			Run:         packRunner(spec),
		})
	}
	return out, nil
}
