// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceOM/core/internal/workload"
)

func TestGuestMountsLinuxRoot(t *testing.T) {
	var mounted, unmounted []string
	g := &guest{
		findDevice: func(context.Context, string) (string, error) { return "/dev/nvme1n1", nil },
		partitions: func(string) []string { return []string{"/dev/nvme1n1p1", "/dev/nvme1n1p2"} },
		isLVM:      func(string) bool { return false },
		mount: func(device, target string) error {
			mounted = append(mounted, device)
			if device == "/dev/nvme1n1p2" {
				if err := os.MkdirAll(filepath.Join(target, "var/lib/dpkg"), 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(target, "var/lib/dpkg/status"), []byte("Package: bash\n"), 0o644)
			}
			return nil
		},
		unmount: func(target string) error {
			unmounted = append(unmounted, target)
			return nil
		},
		isRoot: workload.HasPackageDB,
	}
	root, cleanup, err := g.MountReadOnly(context.Background(), "vol-1")
	if err != nil {
		t.Fatal(err)
	}
	if !workload.HasPackageDB(root) {
		t.Fatal("mounted a filesystem without a package database")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(mounted) != 2 || mounted[1] != "/dev/nvme1n1p2" {
		t.Fatalf("mounted %v", mounted)
	}
	if len(unmounted) != 2 {
		t.Fatalf("unmounted %d filesystems", len(unmounted))
	}
}

func TestGuestSkipsLVM(t *testing.T) {
	g := &guest{
		findDevice: func(context.Context, string) (string, error) { return "/dev/nvme1n1", nil },
		partitions: func(string) []string { return nil },
		isLVM:      func(string) bool { return true },
		mount: func(string, string) error {
			t.Fatal("LVM device was mounted")
			return nil
		},
		unmount: func(string) error { return nil },
		isRoot:  workload.HasPackageDB,
	}
	_, _, err := g.MountReadOnly(context.Background(), "vol-1")
	if err != workload.ErrLVM {
		t.Fatalf("err = %v", err)
	}
}

func TestDiskByIDSkipsPartitions(t *testing.T) {
	names := []string{
		"nvme-Amazon_Elastic_Block_Store_vol0abc-part1",
		"nvme-Amazon_Elastic_Block_Store_vol0abc",
		"nvme-Amazon_Elastic_Block_Store_vol0abcdef",
	}
	if got := diskByID(names, "vol-0abc"); got != "nvme-Amazon_Elastic_Block_Store_vol0abc" {
		t.Fatalf("disk = %s", got)
	}
}
