// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/OpenSourceOM/core/internal/workload"
)

// ImagePermissions are the Azure RBAC actions om scan workload image azure adds.
// The image itself is not deleted. om scan azure does not gain these actions.
var ImagePermissions = []string{
	"Microsoft.Compute/virtualMachines/read",
	"Microsoft.Compute/images/read",
	"Microsoft.Compute/galleries/images/versions/read",
	"Microsoft.Compute/disks/write",
	"Microsoft.Compute/disks/delete",
	"Microsoft.Compute/virtualMachines/attachDetachDataDisks/action",
}

// ImageVM is a virtual machine launched from one boot image.
type ImageVM struct {
	Name          string
	ResourceGroup string
}

// BootImage is one managed, gallery, community, or marketplace image.
type BootImage struct {
	Key       string
	ID        string
	Name      string
	Location  string
	OS        string
	Source    string
	Status    string
	Instances []ImageVM
}

// ImageResult is one boot image after the disk created for the read is deleted.
// Packages is the image walk only.
type ImageResult struct {
	BootImage
	Packages []string
	Skipped  string
}

// ImageAPI is the image-disk lifecycle. Create calls wait until the disk is ready.
// A non-empty name is deleted even when create returns an error.
type ImageAPI interface {
	ListBootImages(ctx context.Context, worker Worker) ([]BootImage, []int32, error)
	CreateDiskFromImage(ctx context.Context, group, location string, image BootImage, zones []string) (string, error)
	DeleteDisk(ctx context.Context, group, name string) error
	Attach(ctx context.Context, group, vm, diskName string, lun int32) error
	Detach(ctx context.Context, group, vm, diskName string) error
}

var _ ImageAPI = (*Client)(nil)

// ImageScanner reads each boot image once and deletes the disk it created.
type ImageScanner struct {
	API     ImageAPI
	Worker  Worker
	Only    []string
	Timeout time.Duration
	Mount   func(ctx context.Context, lun string) (root string, cleanup func() error, err error)
	Walk    func(root string) ([]string, error)
	OnStart func(key, name string)

	cleanupErrs []error
}

// Scan reads each Linux boot image in the worker's region and calls write
// after that image's disk is deleted. A skip leaves packages unchanged.
func (s *ImageScanner) Scan(ctx context.Context, write func(ImageResult) error) error {
	if s.Worker.Name == "" || s.Worker.ResourceGroup == "" || s.Worker.Location == "" {
		return fmt.Errorf("worker name, resource group, and location are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing an Azure client, mount, or package walker")
	}
	images, luns, err := s.API.ListBootImages(ctx, s.Worker)
	if err != nil {
		return err
	}
	images, err = selectBootImages(images, s.Only)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	var failed []error
	for _, img := range images {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		res, scanErr := s.scanImage(ictx, img, luns)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", img.Key, err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *ImageScanner) scanImage(ctx context.Context, img BootImage, luns []int32) (ImageResult, error) {
	res := ImageResult{BootImage: img}
	if skip := skipBootImage(img); skip != "" {
		res.Skipped = skip
		return res, nil
	}
	lun, ok := freeLUN(luns)
	if !ok {
		return ImageResult{}, fmt.Errorf("%s: no free LUN on the worker", imageLabel(img))
	}
	if s.OnStart != nil {
		s.OnStart(img.Key, img.Name)
	}
	group := s.Worker.ResourceGroup
	disk, err := s.API.CreateDiskFromImage(ctx, group, normalizeLocation(s.Worker.Location), img, s.Worker.zones())
	if disk != "" {
		defer s.deleteDisk(group, disk)
	}
	if err != nil {
		if cannotSnapshotImage(err) {
			res.Skipped = workload.ErrImageDenied.Error()
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	if err := s.API.Attach(ctx, group, s.Worker.Name, disk, lun); err != nil {
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	defer s.detach(group, disk)

	root, unmount, err := s.Mount(ctx, fmt.Sprintf("%d", lun))
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	defer func() { s.note(unmount()) }()

	pkgs, err := s.Walk(root)
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	res.Packages = pkgs
	return res, nil
}

func (s *ImageScanner) detach(group, disk string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.Detach(ctx, group, s.Worker.Name, disk); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("detach disk %s: %w", disk, err))
	}
}

func (s *ImageScanner) deleteDisk(group, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.DeleteDisk(ctx, group, name); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("delete disk %s: %w", name, err))
	}
}

func (s *ImageScanner) note(err error) {
	if err != nil {
		s.cleanupErrs = append(s.cleanupErrs, err)
	}
}

func skipBootImage(img BootImage) string {
	if strings.EqualFold(img.OS, "windows") {
		return "Windows"
	}
	if img.Status != "" && !strings.EqualFold(img.Status, "Succeeded") {
		return "not available"
	}
	if img.ID == "" {
		return workload.ErrImageDenied.Error()
	}
	return ""
}

func selectBootImages(images []BootImage, only []string) ([]BootImage, error) {
	if len(only) == 0 {
		return images, nil
	}
	var out []BootImage
	for _, want := range only {
		var matched []BootImage
		for _, img := range images {
			if strings.EqualFold(img.Key, want) || strings.EqualFold(img.ID, want) || strings.EqualFold(img.Name, want) {
				matched = append(matched, img)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("image %s is not in this region", want)
		}
		if len(matched) > 1 {
			return nil, fmt.Errorf("image %s matches more than one image; pass the image id", want)
		}
		out = append(out, matched[0])
	}
	return out, nil
}

func imageLabel(img BootImage) string {
	if img.Name != "" && !strings.EqualFold(img.Name, img.Key) {
		return img.Name
	}
	if img.ID != "" {
		return img.ID
	}
	return img.Key
}

// ListBootImages returns managed images in the worker's region, images that
// virtual machines there were launched from, and the worker's data-disk LUNs.
func (c *Client) ListBootImages(ctx context.Context, worker Worker) ([]BootImage, []int32, error) {
	if worker.Name == "" || worker.ResourceGroup == "" || worker.Location == "" {
		return nil, nil, fmt.Errorf("worker name, resource group, and location are required")
	}
	machines, err := c.List(ctx, normalizeLocation(worker.Location))
	if err != nil {
		return nil, nil, err
	}
	found, err := findMachine(machines, worker.ResourceGroup+"/"+worker.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("worker %s/%s is not in %s", worker.ResourceGroup, worker.Name, normalizeLocation(worker.Location))
	}
	listed, err := c.listManagedImages(ctx)
	if err != nil {
		return nil, nil, err
	}
	return assembleBootImages(worker.Location, c.sub, machines, listed), found.DataLUNs, nil
}

func (c *Client) listManagedImages(ctx context.Context) ([]BootImage, error) {
	if c.images == nil {
		return nil, fmt.Errorf("azure image client is not configured")
	}
	pager := c.images.NewListPager(nil)
	var out []BootImage
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list images: %w", err)
		}
		for _, img := range page.Value {
			item, ok := bootImageFrom(img)
			if ok {
				out = append(out, item)
			}
		}
	}
	return out, nil
}

func bootImageFrom(img *armcompute.Image) (BootImage, bool) {
	if img == nil || img.ID == nil || *img.ID == "" {
		return BootImage{}, false
	}
	item := BootImage{
		ID:       *img.ID,
		Key:      strings.ToLower(*img.ID),
		Name:     value(img.Name),
		Location: normalizeLocation(value(img.Location)),
		Source:   "managed",
	}
	if img.Properties != nil {
		item.Status = value(img.Properties.ProvisioningState)
		if img.Properties.StorageProfile != nil && img.Properties.StorageProfile.OSDisk != nil && img.Properties.StorageProfile.OSDisk.OSType != nil {
			item.OS = strings.ToLower(string(*img.Properties.StorageProfile.OSDisk.OSType))
		}
	}
	return item, true
}

// CreateDiskFromImage creates a managed disk from a boot image in the worker's group.
func (c *Client) CreateDiskFromImage(ctx context.Context, group, location string, image BootImage, zones []string) (string, error) {
	name := objectName(image.Name)
	poller, err := c.disks.BeginCreateOrUpdate(ctx, group, name, imageDiskBody(location, image, zones), nil)
	if err != nil {
		return "", fmt.Errorf("create disk: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return name, fmt.Errorf("create disk: %w", err)
	}
	return name, nil
}

func imageDiskBody(location string, image BootImage, zones []string) armcompute.Disk {
	data := &armcompute.CreationData{CreateOption: ptr(armcompute.DiskCreateOptionFromImage)}
	switch image.Source {
	case "gallery":
		data.GalleryImageReference = &armcompute.ImageDiskReference{ID: ptr(image.ID)}
	case "community":
		data.ImageReference = &armcompute.ImageDiskReference{CommunityGalleryImageID: ptr(image.ID)}
	default:
		data.ImageReference = &armcompute.ImageDiskReference{ID: ptr(image.ID)}
	}
	disk := armcompute.Disk{
		Location: ptr(location),
		Tags:     imageScanTags(image.Name),
		Properties: &armcompute.DiskProperties{
			NetworkAccessPolicy: ptr(armcompute.NetworkAccessPolicyDenyAll),
			PublicNetworkAccess: ptr(armcompute.PublicNetworkAccessDisabled),
			CreationData:        data,
		},
	}
	if len(zones) > 0 {
		disk.Zones = make([]*string, len(zones))
		for i, zone := range zones {
			disk.Zones[i] = ptr(zone)
		}
	}
	return disk
}

func imageScanTags(name string) map[string]*string {
	if len(name) > 256 {
		name = name[:256]
	}
	return map[string]*string{
		"opensourceom:scan":  ptr("workload"),
		"opensourceom:image": ptr(name),
	}
}

func imageRefOf(ref *armcompute.ImageReference) (key, id, source, publisher, offer, sku, version string) {
	if ref == nil {
		return "", "", "", "", "", "", ""
	}
	if v := value(ref.ID); v != "" {
		source = "managed"
		if strings.Contains(strings.ToLower(v), "/galleries/") {
			source = "gallery"
		}
		return strings.ToLower(v), v, source, "", "", "", ""
	}
	if v := value(ref.SharedGalleryImageID); v != "" {
		return strings.ToLower(v), v, "gallery", "", "", "", ""
	}
	if v := value(ref.CommunityGalleryImageID); v != "" {
		return strings.ToLower(v), v, "community", "", "", "", ""
	}
	publisher = value(ref.Publisher)
	offer = value(ref.Offer)
	sku = value(ref.SKU)
	version = value(ref.Version)
	if exact := value(ref.ExactVersion); exact != "" {
		version = exact
	}
	if publisher == "" {
		return "", "", "", "", "", "", ""
	}
	key = strings.ToLower(publisher + "|" + offer + "|" + sku + "|" + version)
	return key, "", "marketplace", publisher, offer, sku, version
}

func marketplaceImageID(subscription, location, publisher, offer, sku, version string) string {
	return "/subscriptions/" + subscription +
		"/providers/Microsoft.Compute/locations/" + normalizeLocation(location) +
		"/publishers/" + publisher +
		"/artifacttypes/vmimage/offers/" + offer +
		"/skus/" + sku +
		"/versions/" + version
}

func assembleBootImages(location, subscription string, machines []Machine, listed []BootImage) []BootImage {
	location = normalizeLocation(location)
	by := map[string]BootImage{}
	var keys []string
	touch := func(key string) {
		if _, ok := by[key]; ok {
			return
		}
		by[key] = BootImage{Key: key}
		keys = append(keys, key)
	}
	for _, src := range listed {
		key := strings.ToLower(src.ID)
		if key == "" {
			key = src.Key
		}
		if key == "" {
			continue
		}
		touch(key)
		img := by[key]
		img.ID = src.ID
		img.Name = src.Name
		img.Location = normalizeLocation(src.Location)
		img.OS = src.OS
		img.Source = src.Source
		if img.Source == "" {
			img.Source = "managed"
		}
		img.Status = src.Status
		img.Key = key
		by[key] = img
	}

	windows := map[string]bool{}
	seen := map[string]int{}
	for _, vm := range machines {
		if vm.Location != "" && !sameLocation(vm.Location, location) {
			continue
		}
		if vm.ImageKey == "" {
			continue
		}
		touch(vm.ImageKey)
		img := by[vm.ImageKey]
		if img.Source == "" {
			img.Source = vm.ImageSource
		}
		if img.ID == "" {
			img.ID = vm.ImageID
		}
		if img.Source == "marketplace" && img.ID == "" && subscription != "" && vm.Publisher != "" && vm.ImageVersion != "" {
			img.ID = marketplaceImageID(subscription, location, vm.Publisher, vm.Offer, vm.SKU, vm.ImageVersion)
		}
		if img.Name == "" {
			img.Name = vm.Offer
			if img.Name == "" {
				img.Name = vm.Name
			}
		}
		if img.Location == "" {
			img.Location = location
		}
		if img.OS == "" && vm.OS != "" && !strings.EqualFold(vm.OS, "windows") {
			img.OS = vm.OS
		}
		if !hasVM(img.Instances, vm.ResourceGroup, vm.Name) {
			img.Instances = append(img.Instances, ImageVM{Name: vm.Name, ResourceGroup: vm.ResourceGroup})
		}
		if seen[vm.ImageKey] == 0 {
			windows[vm.ImageKey] = strings.EqualFold(vm.OS, "windows")
		} else if !strings.EqualFold(vm.OS, "windows") {
			windows[vm.ImageKey] = false
		}
		seen[vm.ImageKey]++
		by[vm.ImageKey] = img
	}

	var out []BootImage
	for _, key := range keys {
		img := by[key]
		if img.OS == "" && windows[key] && seen[key] > 0 {
			img.OS = "windows"
		}
		if img.Location != "" && !sameLocation(img.Location, location) && len(img.Instances) == 0 {
			continue
		}
		slices.SortFunc(img.Instances, func(a, b ImageVM) int {
			if c := strings.Compare(strings.ToLower(a.ResourceGroup), strings.ToLower(b.ResourceGroup)); c != 0 {
				return c
			}
			return strings.Compare(a.Name, b.Name)
		})
		out = append(out, img)
	}
	slices.SortFunc(out, func(a, b BootImage) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func hasVM(vms []ImageVM, group, name string) bool {
	for _, vm := range vms {
		if strings.EqualFold(vm.ResourceGroup, group) && vm.Name == name {
			return true
		}
	}
	return false
}

func cannotSnapshotImage(err error) bool {
	if err == nil {
		return false
	}
	var resp *azcore.ResponseError
	if errors.As(err, &resp) {
		switch resp.StatusCode {
		case http.StatusForbidden, http.StatusConflict:
			return true
		}
		code := strings.ToLower(resp.ErrorCode)
		if strings.Contains(code, "authorization") || strings.Contains(code, "marketplace") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "authorizationfailed") || strings.Contains(msg, "marketplace") || strings.Contains(msg, "not purchased")
}
