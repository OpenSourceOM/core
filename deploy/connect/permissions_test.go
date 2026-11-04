// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	awsv "github.com/OpenSourceOM/core/internal/workload/aws"
	azurev "github.com/OpenSourceOM/core/internal/workload/azure"
	gcpv "github.com/OpenSourceOM/core/internal/workload/gcp"
)

func TestConnectTemplatesMatchPermissions(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Dir(file)
	check(t, filepath.Join(root, "aws/production"), awsv.Permissions, []string{"ec2:AttachVolume", "ec2:CopySnapshot", "ec2:CreateVolume"})
	check(t, filepath.Join(root, "aws/scanner"), awsv.WorkerPermissions, []string{"ec2:CreateSnapshot", "ec2:ModifySnapshotAttribute"})
	check(t, filepath.Join(root, "azure/production"), azurev.Permissions, []string{"Microsoft.Compute/virtualMachines/attachDetachDataDisks/action", "Microsoft.Compute/disks/write"})
	check(t, filepath.Join(root, "azure/scanner"), azurev.WorkerPermissions, []string{"Microsoft.Compute/snapshots/write"})
	check(t, filepath.Join(root, "gcp/production"), gcpv.Permissions, []string{"compute.instances.attachDisk", "compute.disks.create"})
	check(t, filepath.Join(root, "gcp/scanner"), gcpv.WorkerPermissions, []string{"compute.disks.createSnapshot", "compute.snapshots.create"})
}

func check(t *testing.T, dir string, want, forbid []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch filepath.Ext(entry.Name()) {
		case ".tf", ".yaml", ".sh", ".json":
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	if len(files) == 0 {
		t.Fatalf("no templates in %s", dir)
	}
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, action := range want {
			if !hasAction(text, action) {
				t.Errorf("%s missing %s", path, action)
			}
		}
		for _, action := range forbid {
			if hasAction(text, action) {
				t.Errorf("%s grants %s", path, action)
			}
		}
	}
}

func hasAction(body, action string) bool {
	rest := body
	for {
		i := strings.Index(rest, action)
		if i < 0 {
			return false
		}
		end := i + len(action)
		nextOK := end >= len(rest) || strings.ContainsRune("\"', \n\t]", rune(rest[end]))
		prevOK := i == 0 || strings.ContainsRune("\"', [\n\t", rune(rest[i-1]))
		if nextOK && prevOK {
			return true
		}
		rest = rest[end:]
	}
}
