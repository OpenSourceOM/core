// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
	azurev "github.com/OpenSourceOM/core/internal/workload/azure"
	gcpv "github.com/OpenSourceOM/core/internal/workload/gcp"
	"github.com/spf13/cobra"
)

func TestScanWorkloadRegistered(t *testing.T) {
	var workloadCmd *cobra.Command
	for _, command := range scanCmd.Commands() {
		if command.Name() == "workload" {
			workloadCmd = command
			break
		}
	}
	if workloadCmd == nil {
		t.Fatal("om scan workload is not registered")
	}
	if workloadCmd.Runnable() {
		t.Fatal("om scan workload runs a scan; name the cloud")
	}
	aws := commandByName(t, workloadCmd, "aws")
	for _, action := range awsv.Permissions {
		if !strings.Contains(aws.Long, action) {
			t.Errorf("aws help missing %s", action)
		}
	}
	azure := commandByName(t, workloadCmd, "azure")
	for _, action := range azurev.Permissions {
		if !strings.Contains(azure.Long, action) {
			t.Errorf("azure help missing %s", action)
		}
	}
	gcp := commandByName(t, workloadCmd, "gcp")
	for _, action := range gcpv.Permissions {
		if !strings.Contains(gcp.Long, action) {
			t.Errorf("gcp help missing %s", action)
		}
	}
	image := commandByName(t, workloadCmd, "image")
	if image.Runnable() {
		t.Fatal("om scan workload image runs a scan; name the cloud")
	}
	awsImage := commandByName(t, image, "aws")
	for _, action := range awsv.ImagePermissions {
		if !strings.Contains(awsImage.Long, action) {
			t.Errorf("image aws help missing %s", action)
		}
	}
	azureImage := commandByName(t, image, "azure")
	for _, action := range azurev.ImagePermissions {
		if !strings.Contains(azureImage.Long, action) {
			t.Errorf("image azure help missing %s", action)
		}
	}
	gcpImage := commandByName(t, image, "gcp")
	for _, action := range gcpv.ImagePermissions {
		if !strings.Contains(gcpImage.Long, action) {
			t.Errorf("image gcp help missing %s", action)
		}
	}
}

func commandByName(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, command := range parent.Commands() {
		if command.Name() == name {
			return command
		}
	}
	t.Fatalf("%s is not registered", name)
	return nil
}
