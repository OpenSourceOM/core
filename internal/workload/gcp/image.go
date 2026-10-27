// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

// ImagePermissions are the IAM permissions om scan workload image gcp adds.
// The image itself is not deleted. useToDecrypt is the unwrap a
// customer-managed key needs when the disk keeps that key. om scan gcp does
// not gain these permissions.
var ImagePermissions = []string{
	"compute.instances.list",
	"compute.disks.list",
	"compute.images.list",
	"compute.images.useReadOnly",
	"compute.disks.create",
	"compute.disks.delete",
	"compute.disks.useReadOnly",
	"compute.instances.attachDisk",
	"compute.instances.detachDisk",
	"compute.zoneOperations.get",
	"cloudkms.cryptoKeyVersions.useToDecrypt",
	"cloudkms.cryptoKeyVersions.useToEncrypt",
}

// ImageVM is a GCE instance launched from one boot image.
type ImageVM struct {
	Name string
	Zone string
}

// BootImage is one project image, or an image another project published that
// an instance in this region was launched from.
type BootImage struct {
	Link      string
	Name      string
	OS        string
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
	ListBootImages(ctx context.Context, worker Worker) ([]BootImage, []string, error)
	CreateDiskFromImage(ctx context.Context, zone, imageLink, name string) (string, error)
	DeleteDisk(ctx context.Context, zone, name string) error
	Attach(ctx context.Context, zone, instance, diskName, device string) error
	Detach(ctx context.Context, zone, instance, device string) error
}

var _ ImageAPI = (*Client)(nil)

// ImageScanner reads each boot image once and deletes the disk it created.
type ImageScanner struct {
	API     ImageAPI
	Worker  Worker
	Only    []string
	Timeout time.Duration
	Mount   func(ctx context.Context, device string) (root string, cleanup func() error, err error)
	Walk    func(root string) ([]string, error)
	OnStart func(link, name string)

	cleanupErrs []error
}

// Scan reads each Linux boot image used in the worker's region, plus project
// images that no instance is running, and calls write after that image's disk
// is deleted. A skip leaves packages unchanged.
func (s *ImageScanner) Scan(ctx context.Context, write func(ImageResult) error) error {
	if s.Worker.Name == "" || s.Worker.Zone == "" {
		return fmt.Errorf("worker name and zone are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing a Compute client, mount, or package walker")
	}
	images, devices, err := s.API.ListBootImages(ctx, s.Worker)
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
		res, scanErr := s.scanImage(ictx, img, devices)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", img.Link, err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *ImageScanner) scanImage(ctx context.Context, img BootImage, devices []string) (ImageResult, error) {
	res := ImageResult{BootImage: img}
	if skip := skipBootImage(img); skip != "" {
		res.Skipped = skip
		return res, nil
	}
	device := freeDevice(devices)
	if device == "" {
		return ImageResult{}, fmt.Errorf("%s: no free device name on the worker", imageLabel(img))
	}
	if s.OnStart != nil {
		s.OnStart(img.Link, img.Name)
	}
	disk, err := s.API.CreateDiskFromImage(ctx, s.Worker.Zone, img.Link, img.Name)
	if disk != "" {
		defer s.deleteDisk(s.Worker.Zone, disk)
	}
	if err != nil {
		if cannotSnapshotImage(err) {
			res.Skipped = workload.ErrImageDenied.Error()
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	if err := s.API.Attach(ctx, s.Worker.Zone, s.Worker.Name, disk, device); err != nil {
		return ImageResult{}, fmt.Errorf("%s: %w", imageLabel(img), err)
	}
	defer s.detach(s.Worker.Zone, device)

	root, unmount, err := s.Mount(ctx, device)
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

func (s *ImageScanner) detach(zone, device string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.Detach(ctx, zone, s.Worker.Name, device); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("detach disk %s: %w", device, err))
	}
}

func (s *ImageScanner) deleteDisk(zone, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.DeleteDisk(ctx, zone, name); err != nil && !isNotFound(err) {
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
	if img.Status != "" && !strings.EqualFold(img.Status, "READY") {
		return "not available"
	}
	if img.Link == "" {
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
			if img.Link == want || imageKey(img.Link) == imageKey(want) || img.Name == want || lastSegment(img.Link) == want {
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
	if img.Name != "" && img.Name != img.Link {
		return img.Name
	}
	if img.Link != "" {
		return img.Link
	}
	return img.Name
}

// ListBootImages returns project images and images that instances in the
// worker's region were launched from, plus the worker's device names.
func (c *Client) ListBootImages(ctx context.Context, worker Worker) ([]BootImage, []string, error) {
	if worker.Name == "" || worker.Zone == "" {
		return nil, nil, fmt.Errorf("worker name and zone are required")
	}
	instances, err := c.List(ctx, worker.Region())
	if err != nil {
		return nil, nil, err
	}
	sources, err := c.diskImages(ctx, worker.Region())
	if err != nil {
		return nil, nil, err
	}
	for i := range instances {
		instances[i].SourceImage = sources[imageKey(instances[i].BootSource)]
	}
	listed, err := c.projectImages(ctx)
	if err != nil {
		return nil, nil, err
	}
	found, err := findInstance(instances, worker.Zone+"/"+worker.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("worker %s/%s is not in %s", worker.Zone, worker.Name, worker.Region())
	}
	return assembleGCE(listed, instances), found.Devices, nil
}

func (c *Client) projectImages(ctx context.Context) ([]BootImage, error) {
	var out []BootImage
	err := c.svc.Images.List(c.project).Pages(ctx, func(list *compute.ImageList) error {
		for _, img := range list.Items {
			item, ok := bootImageFrom(c.project, img)
			if ok {
				out = append(out, item)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	return out, nil
}

func bootImageFrom(project string, img *compute.Image) (BootImage, bool) {
	if img == nil || img.Name == "" {
		return BootImage{}, false
	}
	link := img.SelfLink
	if link == "" {
		link = "projects/" + project + "/global/images/" + img.Name
	}
	item := BootImage{Link: imageKey(link), Name: img.Name, Status: img.Status}
	if gceImageWindows(img) {
		item.OS = "windows"
	}
	return item, true
}

func gceImageWindows(img *compute.Image) bool {
	if img == nil {
		return false
	}
	for _, feature := range img.GuestOsFeatures {
		if feature != nil && strings.EqualFold(feature.Type, "WINDOWS") {
			return true
		}
	}
	for _, license := range img.Licenses {
		if strings.Contains(strings.ToLower(license), "windows") {
			return true
		}
	}
	return false
}

func (c *Client) diskImages(ctx context.Context, region string) (map[string]string, error) {
	out := map[string]string{}
	err := c.svc.Disks.AggregatedList(c.project).Pages(ctx, func(resp *compute.DiskAggregatedList) error {
		for zonePath, scoped := range resp.Items {
			zone := lastSegment(zonePath)
			if regionOf(zone) != region {
				continue
			}
			for _, disk := range scoped.Disks {
				if disk == nil || disk.SourceImage == "" {
					continue
				}
				src := imageKey(disk.SourceImage)
				if disk.SelfLink != "" {
					out[imageKey(disk.SelfLink)] = src
				}
				if disk.Name != "" && zone != "" {
					out[imageKey("projects/"+c.project+"/zones/"+zone+"/disks/"+disk.Name)] = src
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}
	return out, nil
}

// CreateDiskFromImage creates a disk from a boot image in the worker's zone.
func (c *Client) CreateDiskFromImage(ctx context.Context, zone, imageLink, name string) (string, error) {
	diskName := objectName(name)
	op, err := c.svc.Disks.Insert(c.project, zone, imageDiskBody(diskName, zone, imageLink)).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("create disk: %w", err)
	}
	if err := c.wait(ctx, op); err != nil {
		return diskName, fmt.Errorf("create disk: %w", err)
	}
	return diskName, nil
}

func imageDiskBody(name, zone, imageLink string) *compute.Disk {
	return &compute.Disk{
		Name:        name,
		Description: "OpenSourceOM workload package inventory",
		SourceImage: imageKey(imageLink),
		Type:        "zones/" + zone + "/diskTypes/pd-balanced",
		Labels:      imageLabels(imageLink),
	}
}

func imageLabels(imageLink string) map[string]string {
	return map[string]string{
		"opensourceom-scan":  "workload",
		"opensourceom-image": labelValue(lastSegment(imageLink)),
	}
}

func imageKey(link string) string {
	link = strings.TrimSpace(link)
	link = strings.TrimPrefix(link, "https://www.googleapis.com/compute/v1/")
	link = strings.TrimPrefix(link, "http://www.googleapis.com/compute/v1/")
	return strings.Trim(link, "/")
}

func assembleGCE(listed []BootImage, instances []Instance) []BootImage {
	by := map[string]BootImage{}
	var keys []string
	put := func(img BootImage) string {
		key := imageKey(img.Link)
		if key == "" {
			key = img.Name
		}
		img.Link = key
		prev, ok := by[key]
		if !ok {
			if img.Name == "" {
				img.Name = lastSegment(key)
			}
			by[key] = img
			keys = append(keys, key)
			return key
		}
		if prev.Name == "" || prev.Name == lastSegment(key) {
			if img.Name != "" {
				prev.Name = img.Name
			}
		}
		if img.OS != "" {
			prev.OS = img.OS
		}
		if img.Status != "" && prev.Status == "" {
			prev.Status = img.Status
		}
		by[key] = prev
		return key
	}
	for _, img := range listed {
		put(img)
	}
	windows := map[string]bool{}
	count := map[string]int{}
	for _, inst := range instances {
		key := imageKey(inst.SourceImage)
		if key == "" {
			continue
		}
		put(BootImage{Link: key})
		img := by[key]
		if !hasVM(img.Instances, inst.Zone, inst.Name) {
			img.Instances = append(img.Instances, ImageVM{Name: inst.Name, Zone: inst.Zone})
		}
		by[key] = img
		if count[key] == 0 {
			windows[key] = inst.Windows
		} else if !inst.Windows {
			windows[key] = false
		}
		count[key]++
	}
	var out []BootImage
	for _, key := range keys {
		img := by[key]
		if img.OS == "" && windows[key] && count[key] > 0 {
			img.OS = "windows"
		}
		slices.SortFunc(img.Instances, func(a, b ImageVM) int {
			if c := strings.Compare(a.Zone, b.Zone); c != 0 {
				return c
			}
			return strings.Compare(a.Name, b.Name)
		})
		out = append(out, img)
	}
	slices.SortFunc(out, func(a, b BootImage) int { return strings.Compare(a.Link, b.Link) })
	return out
}

func hasVM(vms []ImageVM, zone, name string) bool {
	for _, vm := range vms {
		if vm.Zone == zone && vm.Name == name {
			return true
		}
	}
	return false
}

func cannotSnapshotImage(err error) bool {
	if err == nil {
		return false
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) && (gerr.Code == http.StatusForbidden || gerr.Code == http.StatusConflict) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "forbidden") || strings.Contains(msg, "marketplace") || strings.Contains(msg, "not authorized")
}
