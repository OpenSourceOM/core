// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/OpenSourceOM/core/internal/workload"
)

func TestMachineFromImageReference(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/App/providers/Microsoft.Compute/virtualMachines/web"
	imageID := "/subscriptions/sub/resourceGroups/App/providers/Microsoft.Compute/images/golden"
	galleryID := "/subscriptions/sub/resourceGroups/App/providers/Microsoft.Compute/galleries/g/images/golden/versions/1"
	vm := &armcompute.VirtualMachine{
		Name:     ptr("web"),
		ID:       ptr(id),
		Location: ptr("eastus"),
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{ID: ptr(imageID)},
				OSDisk:         &armcompute.OSDisk{OSType: ptr(armcompute.OperatingSystemTypesLinux)},
			},
		},
	}
	got, ok := machineFrom(vm)
	if !ok || got.ImageID != imageID || got.ImageSource != "managed" || got.ImageKey != strings.ToLower(imageID) {
		t.Fatalf("machine = %#v ok=%v", got, ok)
	}
	vm.Properties.StorageProfile.ImageReference.ID = ptr(galleryID)
	got, _ = machineFrom(vm)
	if got.ImageSource != "gallery" || got.ImageID != galleryID {
		t.Fatalf("gallery = %#v", got)
	}
}

func TestImagePermissionsDoNotSnapshot(t *testing.T) {
	if !slices.Contains(ImagePermissions, "Microsoft.Compute/images/read") || !slices.Contains(ImagePermissions, "Microsoft.Compute/disks/write") {
		t.Fatalf("permissions = %v", ImagePermissions)
	}
	for _, action := range ImagePermissions {
		if strings.Contains(action, "snapshots") {
			t.Errorf("image scan must not use %s", action)
		}
	}
}

func TestAssembleBootImagesOncePerImage(t *testing.T) {
	imageID := "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/images/golden"
	listed := []BootImage{{
		ID: imageID, Name: "golden", Location: "eastus", OS: "linux", Source: "managed", Status: "Succeeded",
	}}
	machines := []Machine{
		{Name: "web", ResourceGroup: "app", Location: "eastus", OS: "linux", ImageKey: strings.ToLower(imageID), ImageID: imageID, ImageSource: "managed"},
		{Name: "api", ResourceGroup: "app", Location: "eastus", OS: "linux", ImageKey: strings.ToLower(imageID), ImageID: imageID, ImageSource: "managed"},
		{Name: "other", ResourceGroup: "app", Location: "westus", OS: "linux", ImageKey: "other"},
	}
	got := assembleBootImages("eastus", "sub", machines, listed)
	if len(got) != 1 || len(got[0].Instances) != 2 {
		t.Fatalf("images = %#v", got)
	}
	if got[0].Instances[0].Name != "api" || got[0].Instances[1].Name != "web" {
		t.Fatalf("instances = %#v", got[0].Instances)
	}
}

func TestAssembleBootImagesKeepsAnUnusedImageAndBuildsMarketplaceID(t *testing.T) {
	idle := "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/images/idle"
	west := "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/images/west"
	listed := []BootImage{
		{ID: idle, Name: "idle", Location: "eastus", Source: "managed", Status: "Succeeded"},
		{ID: west, Name: "west", Location: "westus", Source: "managed", Status: "Succeeded"},
	}
	machines := []Machine{{
		Name: "web", ResourceGroup: "app", Location: "eastus", OS: "linux",
		ImageKey:    "canonical|0001-com-ubuntu-server-jammy|22_04-lts-gen2|22.04.202410020",
		ImageSource: "marketplace", Publisher: "canonical", Offer: "0001-com-ubuntu-server-jammy",
		SKU: "22_04-lts-gen2", ImageVersion: "22.04.202410020",
	}}
	got := assembleBootImages("eastus", "sub", machines, listed)
	if len(got) != 2 {
		t.Fatalf("images = %#v", got)
	}
	var idleSeen, marketSeen bool
	for _, img := range got {
		if img.Name == "west" {
			t.Fatal("image in another region with no instances was kept")
		}
		if img.Name == "idle" && len(img.Instances) == 0 {
			idleSeen = true
		}
		if img.Source == "marketplace" {
			marketSeen = true
			if !strings.Contains(img.ID, "/publishers/canonical/") || !strings.Contains(img.ID, "/versions/22.04.202410020") {
				t.Fatalf("marketplace id = %s", img.ID)
			}
			if len(img.Instances) != 1 || img.Instances[0].Name != "web" {
				t.Fatalf("marketplace instances = %#v", img.Instances)
			}
		}
	}
	if !idleSeen || !marketSeen {
		t.Fatalf("images = %#v", got)
	}
}

func TestAssembleBootImagesMarksWindows(t *testing.T) {
	got := assembleBootImages("eastus", "sub", []Machine{{
		Name: "win", ResourceGroup: "app", Location: "eastus", OS: "windows",
		ImageKey: "win-image", ImageID: "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/images/win",
		ImageSource: "managed",
	}}, nil)
	if len(got) != 1 || got[0].OS != "windows" {
		t.Fatalf("images = %#v", got)
	}
}

func TestImageDiskBodyUsesTheImageAndNotASnapshot(t *testing.T) {
	managed := imageDiskBody("eastus", BootImage{ID: "/subscriptions/sub/images/golden", Name: "golden", Source: "managed"}, []string{"1"})
	if managed.Properties.CreationData.CreateOption == nil || *managed.Properties.CreationData.CreateOption != armcompute.DiskCreateOptionFromImage {
		t.Fatalf("create option = %v", managed.Properties.CreationData.CreateOption)
	}
	if managed.Properties.CreationData.SourceResourceID != nil {
		t.Fatal("disk copies a snapshot")
	}
	if managed.Properties.CreationData.ImageReference == nil || value(managed.Properties.CreationData.ImageReference.ID) == "" {
		t.Fatal("missing image reference")
	}
	if managed.Properties.NetworkAccessPolicy == nil || *managed.Properties.NetworkAccessPolicy != armcompute.NetworkAccessPolicyDenyAll {
		t.Fatal("disk can be exported")
	}
	gallery := imageDiskBody("eastus", BootImage{ID: "/subscriptions/sub/galleries/g/images/golden/versions/1", Name: "golden", Source: "gallery"}, nil)
	if gallery.Properties.CreationData.GalleryImageReference == nil {
		t.Fatal("gallery image was stored as a managed image")
	}
}

func TestScanImageOnceAppliesTheSamePackages(t *testing.T) {
	imageID := "/subscriptions/sub/resourceGroups/app/providers/Microsoft.Compute/images/golden"
	fake := &fakeImages{images: []BootImage{{
		Key: strings.ToLower(imageID), ID: imageID, Name: "golden", Location: "eastus", OS: "linux", Source: "managed", Status: "Succeeded",
		Instances: []ImageVM{{Name: "api", ResourceGroup: "app"}, {Name: "web", ResourceGroup: "app"}},
	}}}
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
	if len(fake.creates) != 1 || slices.Contains(fake.log, "CreateSnapshot") {
		t.Fatalf("log=%v creates=%d", fake.log, len(fake.creates))
	}
	if len(fake.live) != 0 {
		t.Fatal("disk left behind")
	}
}

func TestScanImageReportsMarketplaceItCannotSnapshot(t *testing.T) {
	fake := &fakeImages{images: []BootImage{{
		Key: "canonical|ubuntu|22_04|1", ID: "/subscriptions/sub/providers/Microsoft.Compute/locations/eastus/publishers/canonical/artifacttypes/vmimage/offers/ubuntu/skus/22_04/versions/1",
		Name: "ubuntu", Source: "marketplace",
		Instances: []ImageVM{{Name: "web", ResourceGroup: "app"}},
	}}, deny: "marketplace"}
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
		t.Fatalf("log=%v live=%d", fake.log, len(fake.live))
	}
}

func TestScanImageSkipsWindows(t *testing.T) {
	fake := &fakeImages{images: []BootImage{{
		Key: "win", ID: "/subscriptions/sub/images/win", Name: "win", OS: "windows", Source: "managed",
	}}}
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
	fake := &fakeImages{images: []BootImage{{
		Key: "golden", ID: "/subscriptions/sub/images/golden", Name: "golden", Source: "managed", Status: "Succeeded",
	}}}
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
			Name:          "worker",
			ResourceGroup: "scan",
			Location:      "eastus",
			Zone:          "1",
		},
		Mount: mount,
		Walk:  walk,
	}
}

type fakeImages struct {
	images  []BootImage
	luns    []int32
	log     []string
	live    map[string]bool
	deny    string
	creates []BootImage
	diskN   int
}

func (f *fakeImages) ListBootImages(context.Context, Worker) ([]BootImage, []int32, error) {
	f.log = append(f.log, "ListBootImages")
	return f.images, f.luns, nil
}

func (f *fakeImages) CreateDiskFromImage(_ context.Context, _, _ string, image BootImage, _ []string) (string, error) {
	f.log = append(f.log, "CreateDisk")
	f.creates = append(f.creates, image)
	if f.deny != "" && image.Source == f.deny {
		return "", errors.New("AuthorizationFailed: marketplace plan was not purchased")
	}
	if f.live == nil {
		f.live = map[string]bool{}
	}
	f.diskN++
	name := "disk"
	f.live[name] = true
	return name, nil
}

func (f *fakeImages) DeleteDisk(_ context.Context, _, name string) error {
	f.log = append(f.log, "DeleteDisk")
	delete(f.live, name)
	return nil
}

func (f *fakeImages) Attach(context.Context, string, string, string, int32) error {
	f.log = append(f.log, "Attach")
	return nil
}

func (f *fakeImages) Detach(context.Context, string, string, string) error {
	f.log = append(f.log, "Detach")
	return nil
}
