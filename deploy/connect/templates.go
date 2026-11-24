// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"embed"
	"fmt"
)

//go:embed aws azure gcp
var Templates embed.FS

// TemplateFiles are the grants the connect screen can download.
var TemplateFiles = map[string]string{
	"aws-inventory":    "aws/inventory/cloudformation.yaml",
	"aws-scanner":      "aws/scanner/cloudformation.yaml",
	"aws-production":   "aws/production/cloudformation.yaml",
	"azure-inventory":  "azure/inventory/apply.sh",
	"azure-scanner":    "azure/scanner/apply.sh",
	"azure-production": "azure/production/apply.sh",
	"gcp-inventory":    "gcp/inventory/apply.sh",
	"gcp-scanner":      "gcp/scanner/apply.sh",
	"gcp-production":   "gcp/production/apply.sh",
}

// ReadTemplate returns one connect grant by its public name.
func ReadTemplate(name string) ([]byte, error) {
	path, ok := TemplateFiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown template %q", name)
	}
	body, err := Templates.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", name, err)
	}
	return body, nil
}
