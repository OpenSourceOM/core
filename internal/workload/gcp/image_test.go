// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/workload"
	"google.golang.org/api/compute/v1"
)

func TestImagePermissionsDoNotSnapshot(t *testing.T) {
	if !slices.Contains(ImagePermissions, "compute.images.useReadOnly") || !slices.Contains(ImagePermissions, "compute.disks.create") {
		t.Fatalf("permissions = %v", ImagePermissions)
	}
	for _, action := range ImagePermissions {
		if strings.Contains(action, "snapshot") {
			t.Errorf("image scan must not use %s", action)
		}
	}
}

func TestAssembleGCEOncePerImage(t *testing.T) {
	link := "projects/p/global/images/golden"
	listed := []BootImage{{Link: link, Name: "golden", Status: "READY"}, {Link: "projects/p/global/images/idle", Name: "idle", Status: "READY"}}
	instances := []Instance{
		{Name: "web", Zone: "us-central1-a", SourceImage: "https://www.googleapis.com/compute/v1/" + link},
		{Name: "api", Zone: "us-central1-b", SourceImage: link},
		{Name: "deb", Zone: "us-central1-a", SourceImage: "projects/debian-cloud/global/images/debian-12"},
		{Name: "win", Zone: "us-central1-a", Windows: true, SourceImage: "projects/windows-cloud/global/images/windows-2022"},
	}
	got := assembleGCE(listed, instances)
	byLink := map[string]BootImage{}
	for _, img := range got {
		byLink[img.Link] = img
	}
	golden := byLink[link]
	if len(golden.Instances) != 2 || golden.Instances[0].Name != "web" || golden.Instances[1].Name != "api" {
		t.Fatalf("golden = %#v", golden)
	}
	if _, ok := byLink["projects/p/global/images/idle"]; !ok || len(byLink["projects/p/global/images/idle"].Instances) != 0 {
		t.Fatal("unused project image was dropped")
	}
	if len(byLink["projects/debian-cloud/global/images/debian-12"].Instances) != 1 {
		t.Fatal("foreign image was not kept")
	}
	if byLink["projects/windows-cloud/global/images/windows-2022"].OS != "windows" {
		t.Fatal("windows image was not marked")
	}
}

func TestImageDiskBodyUsesTheImageAndNotASnapshot(t *testing.T) {
	body := imageDiskBody("omwl-abc", "us-central1-a", "https://www.googleapis.com/compute/v1/projects/p/global/images/golden")
	if body.SourceSnapshot != "" {
		t.Fatal("disk copies a snapshot")
	}
	if body.SourceImage != "projects/p/global/images/golden" {
		t.Fatalf("source = %s", body.SourceImage)
	}
	if body.Labels["opensourceom-scan"] != "workload" || body.Labels["opensourceom-image"] != "golden" {
		t.Fatalf("labels = %#v", body.Labels)
	}
}

func TestGCEImageWindows(t *testing.T) {
	if !gceImageWindows(&compute.Image{GuestOsFeatures: []*compute.GuestOsFeature{{Type: "WINDOWS"}}}) {
		t.Fatal("guest os feature was ignored")
	}
	if gceImageWindows(&compute.Image{Name: "debian"}) {
		t.Fatal("linux image marked windows")
	}
}

func TestScanImageOnceAppliesTheSamePackages(t *testing.T) {
	link := "projects/p/global/images/golden"
	fake := &fakeImages{images: []BootImage{{
		Link: link, Name: "golden", Status: "READY",
		Instances: []ImageVM{{Name: "api", Zone: "us-central1-b"}, {Name: "web", Zone: "us-central1-a"}},
	}}, devices: []string{"boot"}}
	var mounts int
	scanner := testImageScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		mounts++
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error { return nil }, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.Scan(context.Background(), func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mounts != 1 || len(got) != 1 || len(got[0].Instances) != 2 || got[0].Skipped != "" {
		t.Fatalf("mounts=%d results=%#v", mounts, got)
	}
	joined := strings.Join(got[0].Packages, "\n")
	if !strings.Contains(joined, "pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1") || strings.Contains(joined, "nginx") {
		t.Fatalf("packages =\n%s", joined)
	}
	if len(fake.links) != 1 || fake.links[0] != link || slices.Contains(fake.log, "CreateSnapshot") {
		t.Fatalf("log=%v links=%v", fake.log, fake.links)
	}
	if len(fake.live) != 0 {
		t.Fatal("disk left behind")
	}
}

func TestScanImageReportsMarketplaceItCannotSnapshot(t *testing.T) {
	fake := &fakeImages{images: []BootImage{{
		Link: "projects/marketplace/global/images/paid", Name: "paid", Status: "READY",
		Instances: []ImageVM{{Name: "web", Zone: "us-central1-a"}},
	}}, deny: true}
	scanner := testImageScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("marketplace image was mounted")
		return "", nil, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.Scan(context.Background(), func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != workload.ErrImageDenied.Error() {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "Attach") || len(fake.live) != 0 {
		t.Fatalf("log=%v", fake.log)
	}
}

func TestScanImageSkipsWindows(t *testing.T) {
	fake := &fakeImages{images: []BootImage{{Link: "projects/p/global/images/win", Name: "win", OS: "windows", Status: "READY"}}}
	scanner := testImageScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("windows image was mounted")
		return "", nil, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.Scan(context.Background(), func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != "Windows" || slices.Contains(fake.log, "CreateDisk") {
		t.Fatalf("results=%#v log=%v", got, fake.log)
	}
}

func TestScanImageDeletesDiskWhenWalkFails(t *testing.T) {
	fake := &fakeImages{images: []BootImage{{Link: "projects/p/global/images/golden", Name: "golden", Status: "READY"}}}
	scanner := testImageScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return t.TempDir(), func() error { return nil }, nil
	}, func(string) ([]string, error) {
		return nil, errors.New("read rpm database: corrupt")
	})
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v", err)
	}
	assertOrder(t, fake.log, "CreateDisk", "Attach", "Detach", "DeleteDisk")
	if len(fake.live) != 0 {
		t.Fatal("disk left behind")
	}
}

func testImageScanner(t *testing.T, fake *fakeImages, mount func(context.Context, string) (string, func() error, error), walk func(string) ([]string, error)) *ImageScanner {
	t.Helper()
	return &ImageScanner{
		API: fake,
		Worker: Worker{
			Name: "worker",
			Zone: "us-central1-a",
		},
		Mount: mount,
		Walk:  walk,
	}
}

type fakeImages struct {
	images  []BootImage
	devices []string
	log     []string
	live    map[string]bool
	deny    bool
	links   []string
}

func (f *fakeImages) ListBootImages(context.Context, Worker) ([]BootImage, []string, error) {
	f.log = append(f.log, "ListBootImages")
	return f.images, f.devices, nil
}

func (f *fakeImages) CreateDiskFromImage(_ context.Context, _, imageLink, _ string) (string, error) {
	f.log = append(f.log, "CreateDisk")
	f.links = append(f.links, imageLink)
	if f.deny {
		return "", errors.New("googleapi: Error 403: marketplace image, forbidden")
	}
	if f.live == nil {
		f.live = map[string]bool{}
	}
	f.live["disk"] = true
	return "disk", nil
}

func (f *fakeImages) DeleteDisk(_ context.Context, _, name string) error {
	f.log = append(f.log, "DeleteDisk")
	delete(f.live, name)
	return nil
}

func (f *fakeImages) Attach(context.Context, string, string, string, string) error {
	f.log = append(f.log, "Attach")
	return nil
}

func (f *fakeImages) Detach(context.Context, string, string, string) error {
	f.log = append(f.log, "Detach")
	return nil
}
