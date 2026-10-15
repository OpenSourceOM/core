// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/workload"
	"google.golang.org/api/compute/v1"
)

func TestPermissionsCoverSnapshotLifecycle(t *testing.T) {
	for _, action := range []string{
		"compute.disks.createSnapshot",
		"compute.instances.attachDisk",
		"compute.snapshots.delete",
		"compute.disks.delete",
		"cloudkms.cryptoKeyVersions.useToDecrypt",
	} {
		if !slices.Contains(Permissions, action) {
			t.Errorf("missing %s", action)
		}
	}
}

func TestScanWritesPackagesAndDeletesSnapshot(t *testing.T) {
	fake := newFake(testInstances())
	var unmounted bool
	var got []Result
	scanner := testScanner(t, fake, func(ctx context.Context, device string) (string, func() error, error) {
		if device != "omwl" {
			t.Fatalf("mounted %s", device)
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
	if len(fake.sources) != 1 || fake.sources[0] != "projects/p/zones/us-central1-b/disks/boot" {
		t.Fatalf("sources = %#v", fake.sources)
	}
	if len(fake.zones) != 1 || fake.zones[0] != "us-central1-a" {
		t.Fatalf("disk zones = %#v", fake.zones)
	}
	if len(fake.devices) != 1 || fake.devices[0] != "omwl" {
		t.Fatalf("attach devices=%v", fake.devices)
	}
	if fake.snaps != 0 || fake.disks != 0 {
		t.Fatalf("leftover snaps=%d disks=%d", fake.snaps, fake.disks)
	}
}

func TestScanSkipsWindowsScratchAndCustomerKey(t *testing.T) {
	fake := newFake(append(testInstances(),
		Instance{Name: "win", Zone: "us-central1-b", Status: "RUNNING", Windows: true, BootSource: "projects/p/zones/us-central1-b/disks/win"},
		Instance{Name: "local", Zone: "us-central1-b", Status: "RUNNING", Scratch: true},
		Instance{Name: "csek", Zone: "us-central1-b", Status: "RUNNING", CustomerKey: true, BootSource: "projects/p/zones/us-central1-b/disks/csek"},
	))
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("skipped instance was mounted")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"win", "local", "csek"}
	var got []Result
	if err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Skipped != "Windows" || got[1].Skipped != "no persistent boot disk" || got[2].Skipped != "customer-supplied encryption key" {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "CreateSnapshot") {
		t.Fatalf("snapshot created: %v", fake.log)
	}
}

func TestScanRejectsAmbiguousInstanceName(t *testing.T) {
	instances := testInstances()
	instances = append(instances, Instance{
		Name: "web", Zone: "us-central1-c", Status: "RUNNING",
		BootSource: "projects/p/zones/us-central1-c/disks/boot",
	})
	fake := newFake(instances)
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("ambiguous instance was mounted")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"web"}
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "more than one zone") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanDeletesSnapshotWhenCreateFails(t *testing.T) {
	fake := newFake(testInstances())
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
	fake := newFake(testInstances())
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

func TestAttachedDiskIsReadOnly(t *testing.T) {
	disk := attachedDisk("projects/p/zones/us-central1-a/disks/copy", "omwl")
	if disk.Mode != "READ_ONLY" || disk.Boot || disk.AutoDelete || disk.DeviceName != "omwl" {
		t.Fatalf("disk = %#v", disk)
	}
	if disk.DiskEncryptionKey != nil {
		t.Fatal("attach sets an encryption key")
	}
}

func TestSnapshotStaysInRegion(t *testing.T) {
	body := snapshotBody("omwl-web-abcd", "us-central1", "web")
	if len(body.StorageLocations) != 1 || body.StorageLocations[0] != "us-central1" {
		t.Fatalf("locations = %#v", body.StorageLocations)
	}
	if body.Labels["opensourceom-scan"] != "workload" {
		t.Fatalf("labels = %#v", body.Labels)
	}
	disk := diskBody("omwl-web-abcd", "us-central1-a", "projects/p/global/snapshots/omwl-web-abcd", "web")
	if disk.DiskEncryptionKey != nil {
		t.Fatal("disk sets an encryption key")
	}
}

func TestInstanceFromBootDisk(t *testing.T) {
	got, ok := instanceFrom("us-central1-a", &compute.Instance{
		Name:   "web",
		Status: "RUNNING",
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				DeviceName: "persistent-disk-0",
				Source:     "projects/p/zones/us-central1-a/disks/boot",
				Type:       "PERSISTENT",
				GuestOsFeatures: []*compute.GuestOsFeature{
					{Type: "UEFI_COMPATIBLE"},
				},
			},
			{DeviceName: "data", Source: "projects/p/zones/us-central1-a/disks/data"},
		},
	})
	if !ok || got.Windows || got.BootSource == "" || len(got.Devices) != 2 {
		t.Fatalf("instance = %#v", got)
	}
	win, _ := instanceFrom("us-central1-a", &compute.Instance{
		Name: "win",
		Disks: []*compute.AttachedDisk{{
			Boot:     true,
			Source:   "projects/p/zones/us-central1-a/disks/win",
			Licenses: []string{"https://www.googleapis.com/compute/v1/projects/windows-cloud/global/licenses/windows-server-2022-dc"},
			DiskEncryptionKey: &compute.CustomerEncryptionKey{
				Sha256: "abc",
			},
		}},
	})
	if !win.Windows || !win.CustomerKey {
		t.Fatalf("windows = %#v", win)
	}
}

func TestDiskRef(t *testing.T) {
	zonal, location, name, err := diskRef("https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-b/disks/boot")
	if err != nil || !zonal || location != "us-central1-b" || name != "boot" {
		t.Fatalf("zonal=%v location=%s name=%s err=%v", zonal, location, name, err)
	}
	zonal, location, name, err = diskRef("projects/p/regions/us-central1/disks/boot")
	if err != nil || zonal || location != "us-central1" || name != "boot" {
		t.Fatalf("regional zonal=%v location=%s name=%s err=%v", zonal, location, name, err)
	}
}

func TestRegionOf(t *testing.T) {
	if regionOf("us-central1-a") != "us-central1" || regionOf("europe-west1-b") != "europe-west1" {
		t.Fatal(regionOf("us-central1-a"))
	}
}

func TestCheckProject(t *testing.T) {
	if err := CheckProject("p", "p"); err != nil {
		t.Fatal(err)
	}
	err := CheckProject("other", "p")
	if err == nil || err.Error() != "this instance is in project other; set GCP_PROJECT_ID=other" {
		t.Fatalf("err = %v", err)
	}
}

func TestDevicePaths(t *testing.T) {
	got := devicePaths("omwl")
	if len(got) != 2 || got[0] != "/dev/disk/by-id/google-omwl" {
		t.Fatalf("paths = %#v", got)
	}
}

func testScanner(t *testing.T, fake *fakeAPI, mount func(context.Context, string) (string, func() error, error), walk func(string) ([]string, error)) *Scanner {
	t.Helper()
	return &Scanner{
		API: fake,
		Worker: Worker{
			Name: "worker",
			Zone: "us-central1-a",
		},
		Mount: mount,
		Walk:  walk,
	}
}

func testInstances() []Instance {
	return []Instance{
		{
			Name: "worker", Zone: "us-central1-a", Status: "RUNNING",
			BootSource: "projects/p/zones/us-central1-a/disks/worker",
			Devices:    []string{"persistent-disk-0"},
		},
		{
			Name: "web", Zone: "us-central1-b", Status: "TERMINATED",
			BootSource: "projects/p/zones/us-central1-b/disks/boot",
			Devices:    []string{"persistent-disk-0", "data"},
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
	instances []Instance
	log       []string
	sources   []string
	zones     []string
	devices   []string
	snaps     int
	disks     int
	snapErr   error
	snapName  string
}

func newFake(instances []Instance) *fakeAPI {
	return &fakeAPI{instances: instances}
}

func (f *fakeAPI) List(context.Context, string) ([]Instance, error) { return f.instances, nil }

func (f *fakeAPI) CreateSnapshot(_ context.Context, source, _, _ string) (string, error) {
	f.log = append(f.log, "CreateSnapshot")
	f.sources = append(f.sources, source)
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

func (f *fakeAPI) DeleteSnapshot(context.Context, string) error {
	f.log = append(f.log, "DeleteSnapshot")
	if f.snaps > 0 {
		f.snaps--
	}
	return nil
}

func (f *fakeAPI) CreateDisk(_ context.Context, zone, _, _ string) (string, error) {
	f.log = append(f.log, "CreateDisk")
	f.zones = append(f.zones, zone)
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

func (f *fakeAPI) Attach(_ context.Context, _, _, _, device string) error {
	f.log = append(f.log, "Attach")
	f.devices = append(f.devices, device)
	return nil
}

func (f *fakeAPI) Detach(context.Context, string, string, string) error {
	f.log = append(f.log, "Detach")
	return nil
}
