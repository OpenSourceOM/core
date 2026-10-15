// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
)

func TestScanWorkloadRegistered(t *testing.T) {
	for _, command := range scanCmd.Commands() {
		if command.Name() == "workload" {
			for _, action := range awsv.Permissions {
				if !strings.Contains(command.Long, action) {
					t.Errorf("help missing %s", action)
				}
			}
			return
		}
	}
	t.Fatal("om scan workload is not registered")
}
