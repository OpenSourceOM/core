// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/workload"
)

func TestPermissionsCoverSnapshotLifecycle(t *testing.T) {
	for _, action := range []string{
		"Microsoft.Compute/snapshots/write",
		"Microsoft.Compute/virtualMachines/attachDetachDataDisks/action",
		"Microsoft.Compute/snapshots/delete",
		"Microsoft.Compute/disks/delete",
		"Microsoft.KeyVault/vaults/keys/unwrap/action",
	} {
		if !slices.Contains(Permissions, action) {
			t.Errorf("missing %s", action)
		}
	}
}

func TestScanWritesPackagesAndDeletesSnapshot(t *testing.T) {
	fake := newFake(testMachines())
	var unmounted bool
	var got []Result
	scanner := testScanner(t, fake, func(ctx context.Context, lun string) (string, func() error, error) {
		if lun != "1" {
			t.Fatalf("mounted lun %s", lun)
		}
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error {
			unmounted = true
			return nil
		}, nil
	}, workload.Walk)
	scanner.Only = []string{"web"}

	err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !unmounted {
		t.Fatal("mount was left in place")
	}
	if len(got) != 1 || got[0].Skipped != "" || got[0].Name != "web" {
		t.Fatalf("results = %#v", got)
	}
	joined := strings.Join(got[0].Packages, "\n")
	if !strings.Contains(joined, "pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1") {
		t.Fatalf("packages =\n%s", joined)
	}
	if strings.Contains(joined, "PRIVATE KEY") || strings.Contains(joined, "AKIA") {
		t.Fatalf("file contents leaked:\n%s", joined)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "CreateDisk", "Attach", "Detach", "DeleteDisk", "DeleteSnapshot")
	if len(fake.sources) != 1 || fake.sources[0] != "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/disks/os" {
		t.Fatalf("sources = %#v", fake.sources)
	}
	if len(fake.zones) != 1 || len(fake.zones[0]) != 1 || fake.zones[0][0] != "1" {
		t.Fatalf("zones = %#v", fake.zones)
	}
	if len(fake.luns) != 1 || fake.luns[0] != 1 {
		t.Fatalf("luns = %#v", fake.luns)
	}
	if fake.snaps != 0 || fake.disks != 0 {
		t.Fatalf("leftover snaps=%d disks=%d", fake.snaps, fake.disks)
	}
}

func TestScanSkipsWindowsEphemeralAndUnmanaged(t *testing.T) {
	fake := newFake(append(testMachines(),
		Machine{Name: "win", ResourceGroup: "app", Location: "eastus", OS: "windows", OSDiskID: "disk-win", ProvisioningState: "Succeeded"},
		Machine{Name: "ephemeral", ResourceGroup: "app", Location: "eastus", OS: "linux", Ephemeral: true, OSDiskID: "disk-eph", ProvisioningState: "Succeeded"},
		Machine{Name: "vhd", ResourceGroup: "app", Location: "eastus", OS: "linux", ProvisioningState: "Succeeded"},
	))
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("skipped VM was mounted")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"win", "ephemeral", "vhd"}
	var got []Result
	if err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Skipped != "Windows" || got[1].Skipped != "ephemeral OS disk" || got[2].Skipped != "no managed OS disk" {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "CreateSnapshot") {
		t.Fatalf("snapshot created: %v", fake.log)
	}
}

func TestScanDeletesSnapshotWhenCreateFails(t *testing.T) {
	fake := newFake(testMachines())
	fake.snapErr = errors.New("snapshot failed")
	fake.snapName = "snap-partial"
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("mounted a failed snapshot")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"web"}
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "snapshot failed") {
		t.Fatalf("err = %v", err)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "DeleteSnapshot")
	if fake.snaps != 0 {
		t.Fatal("snapshot left behind")
	}
}

func TestScanDeletesSnapshotWhenWalkFails(t *testing.T) {
	fake := newFake(testMachines())
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return t.TempDir(), func() error { return nil }, nil
	}, func(string) ([]string, error) {
		return nil, errors.New("read dpkg status: corrupt")
	})
	scanner.Only = []string{"web"}
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v", err)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "Attach", "Detach", "DeleteDisk", "DeleteSnapshot")
	if fake.snaps != 0 || fake.disks != 0 {
		t.Fatal("snapshot or disk was left behind")
	}
}

func TestScanRejectsAmbiguousVMName(t *testing.T) {
	machines := testMachines()
	machines = append(machines, Machine{
		Name: "web", ResourceGroup: "other", Location: "eastus", OS: "linux",
		OSDiskID: "disk", ProvisioningState: "Succeeded",
	})
	fake := newFake(machines)
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("ambiguous VM was mounted")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"web"}
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "more than one resource group") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanSkipsLVMAfterCleanup(t *testing.T) {
	fake := newFake(testMachines())
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return "", nil, workload.ErrLVM
	}, func(string) ([]string, error) {
		t.Fatal("LVM root was walked")
		return nil, nil
	})
	scanner.Only = []string{"web"}
	var got []Result
	if err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != workload.ErrLVM.Error() {
		t.Fatalf("results = %#v", got)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "DeleteSnapshot")
	if fake.snaps != 0 || fake.disks != 0 {
		t.Fatal("snapshot or disk left behind")
	}
}

func testScanner(t *testing.T, fake *fakeAPI, mount func(context.Context, string) (string, func() error, error), walk func(string) ([]string, error)) *Scanner {
	t.Helper()
	return &Scanner{
		API: fake,
		Worker: Worker{
			Name:          "worker",
			ResourceGroup: "scan",
			Location:      "eastus",
			Zone:          "1",
		},
		Mount: mount,
		Walk:  walk,
	}
}

func testMachines() []Machine {
	return []Machine{
		{
			Name: "worker", ResourceGroup: "scan", Location: "eastus", OS: "linux",
			OSDiskID:          "/subscriptions/sub/resourceGroups/scan/providers/Microsoft.Compute/disks/worker",
			ProvisioningState: "Succeeded", DataLUNs: []int32{0},
		},
		{
			Name: "web", ResourceGroup: "app", Location: "eastus", OS: "linux",
			OSDiskID:          "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/disks/os",
			ProvisioningState: "Succeeded", DataLUNs: []int32{0, 1},
		},
	}
}

func writeRoot(t *testing.T, root string) {
	t.Helper()
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.1.1n-0ubuntu1\nDescription: library\n BEGIN PRIVATE KEY\n"
	for _, rel := range []string{"etc/os-release", "var/lib/dpkg/status", "home/app/notes.txt"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "home/app/notes.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertOrder(t *testing.T, log []string, steps ...string) {
	t.Helper()
	at := -1
	for _, step := range steps {
		next := slices.Index(log[at+1:], step)
		if next < 0 {
			t.Fatalf("log %v missing %s after position %d", log, step, at)
		}
		at += next + 1
	}
}

type fakeAPI struct {
	machines []Machine
	log      []string
	sources  []string
	zones    [][]string
	luns     []int32
	snaps    int
	disks    int
	snapErr  error
	snapName string
}

func newFake(machines []Machine) *fakeAPI {
	return &fakeAPI{machines: machines}
}

func (f *fakeAPI) List(context.Context, string) ([]Machine, error) {
	return f.machines, nil
}

func (f *fakeAPI) CreateSnapshot(_ context.Context, _, _, sourceDisk, _ string) (string, error) {
	f.log = append(f.log, "CreateSnapshot")
	f.sources = append(f.sources, sourceDisk)
	name := "snap-1"
	if f.snapName != "" {
		name = f.snapName
	}
	if f.snapErr != nil {
		if f.snapName != "" {
			f.snaps++
		}
		return f.snapName, f.snapErr
	}
	f.snaps++
	return name, nil
}

func (f *fakeAPI) DeleteSnapshot(context.Context, string, string) error {
	f.log = append(f.log, "DeleteSnapshot")
	if f.snaps > 0 {
		f.snaps--
	}
	return nil
}

func (f *fakeAPI) CreateDisk(_ context.Context, _, _, _ string, zones []string, _ string) (string, error) {
	f.log = append(f.log, "CreateDisk")
	f.zones = append(f.zones, zones)
	f.disks++
	return "disk-1", nil
}

func (f *fakeAPI) DeleteDisk(context.Context, string, string) error {
	f.log = append(f.log, "DeleteDisk")
	if f.disks > 0 {
		f.disks--
	}
	return nil
}

func (f *fakeAPI) Attach(_ context.Context, _, _, _ string, lun int32) error {
	f.log = append(f.log, "Attach")
	f.luns = append(f.luns, lun)
	return nil
}

func (f *fakeAPI) Detach(context.Context, string, string, string) error {
	f.log = append(f.log, "Detach")
	return nil
}
