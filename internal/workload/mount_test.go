// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPartitionDevices(t *testing.T) {
	got := PartitionDevices("/dev/nvme1n1", []string{"nvme1n1", "nvme1n1p2", "nvme1n1p1", "queue"})
	want := "/dev/nvme1n1p1,/dev/nvme1n1p2"
	if len(got) != 2 || got[0]+","+got[1] != want {
		t.Fatalf("partitions = %v", got)
	}
}

func TestDeviceIsLVM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk")
	buf := make([]byte, 520)
	copy(buf[512:], []byte("LABELONE"))
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	if !DeviceIsLVM(path) {
		t.Fatal("expected an LVM label")
	}
}

func TestSanitizeName(t *testing.T) {
	got := SanitizeName("Web_App.1", "abcd1234", 63)
	if got != "omwl-web-app-1-abcd1234" {
		t.Fatalf("name = %s", got)
	}
	long := SanitizeName("vm-"+strings.Repeat("a", 80), "abcd1234", 63)
	if len(long) > 63 || !strings.HasPrefix(long, "omwl-") || !strings.HasSuffix(long, "-abcd1234") {
		t.Fatalf("name = %s (%d)", long, len(long))
	}
}
