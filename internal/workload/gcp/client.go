// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// Client snapshots boot disks and attaches the copy to the worker read-only.
type Client struct {
	project string
	svc     *compute.Service
}

var _ API = (*Client)(nil)

// NewClient uses application default credentials for the project.
func NewClient(ctx context.Context, projectID string) (*Client, error) {
	svc, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}
	return &Client{project: projectID, svc: svc}, nil
}

func (c *Client) List(ctx context.Context, region string) ([]Instance, error) {
	var out []Instance
	err := c.svc.Instances.AggregatedList(c.project).Pages(ctx, func(resp *compute.InstanceAggregatedList) error {
		for zonePath, scoped := range resp.Items {
			zone := lastSegment(zonePath)
			if regionOf(zone) != region {
				continue
			}
			for _, inst := range scoped.Instances {
				item, ok := instanceFrom(zone, inst)
				if ok {
					out = append(out, item)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	return out, nil
}

func (c *Client) CreateSnapshot(ctx context.Context, source, region, vm string) (string, error) {
	zonal, location, disk, err := diskRef(source)
	if err != nil {
		return "", err
	}
	name := objectName(vm)
	body := snapshotBody(name, region, vm)
	var op *compute.Operation
	if zonal {
		op, err = c.svc.Disks.CreateSnapshot(c.project, location, disk, body).Context(ctx).Do()
	} else {
		op, err = c.svc.RegionDisks.CreateSnapshot(c.project, location, disk, body).Context(ctx).Do()
	}
	if err != nil {
		return "", fmt.Errorf("create snapshot: %w", err)
	}
	if err := c.wait(ctx, op); err != nil {
		return name, fmt.Errorf("create snapshot: %w", err)
	}
	return name, nil
}

func (c *Client) DeleteSnapshot(ctx context.Context, name string) error {
	op, err := c.svc.Snapshots.Delete(c.project, name).Context(ctx).Do()
	if isGCPNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = c.wait(ctx, op)
	if isGCPNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) CreateDisk(ctx context.Context, zone, snapshotName, vm string) (string, error) {
	name := objectName(vm)
	op, err := c.svc.Disks.Insert(c.project, zone, diskBody(name, zone, c.snapshotLink(snapshotName), vm)).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("create disk: %w", err)
	}
	if err := c.wait(ctx, op); err != nil {
		return name, fmt.Errorf("create disk: %w", err)
	}
	return name, nil
}

func (c *Client) DeleteDisk(ctx context.Context, zone, name string) error {
	op, err := c.svc.Disks.Delete(c.project, zone, name).Context(ctx).Do()
	if isGCPNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = c.wait(ctx, op)
	if isGCPNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) Attach(ctx context.Context, zone, instance, diskName, device string) error {
	op, err := c.svc.Instances.AttachDisk(c.project, zone, instance, attachedDisk(c.diskLink(zone, diskName), device)).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("attach disk: %w", err)
	}
	if err := c.wait(ctx, op); err != nil {
		return fmt.Errorf("attach disk: %w", err)
	}
	return nil
}

func (c *Client) Detach(ctx context.Context, zone, instance, device string) error {
	op, err := c.svc.Instances.DetachDisk(c.project, zone, instance, device).Context(ctx).Do()
	if isGCPNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = c.wait(ctx, op)
	if isGCPNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) wait(ctx context.Context, op *compute.Operation) error {
	if op == nil {
		return fmt.Errorf("empty operation")
	}
	for {
		if op.Status == "DONE" {
			return operationError(op)
		}
		var next *compute.Operation
		var err error
		switch {
		case op.Zone != "":
			next, err = c.svc.ZoneOperations.Wait(c.project, lastSegment(op.Zone), op.Name).Context(ctx).Do()
		case op.Region != "":
			next, err = c.svc.RegionOperations.Wait(c.project, lastSegment(op.Region), op.Name).Context(ctx).Do()
		default:
			next, err = c.svc.GlobalOperations.Wait(c.project, op.Name).Context(ctx).Do()
		}
		if err != nil {
			return err
		}
		if next == nil {
			return fmt.Errorf("empty operation")
		}
		op = next
	}
}

func (c *Client) snapshotLink(name string) string {
	return "projects/" + c.project + "/global/snapshots/" + name
}

func (c *Client) diskLink(zone, name string) string {
	return "projects/" + c.project + "/zones/" + zone + "/disks/" + name
}

func snapshotBody(name, region, vm string) *compute.Snapshot {
	return &compute.Snapshot{
		Name:             name,
		Description:      "OpenSourceOM workload package inventory",
		StorageLocations: []string{region},
		Labels:           scanLabels(vm),
	}
}

func diskBody(name, zone, snapshotLink, vm string) *compute.Disk {
	return &compute.Disk{
		Name:           name,
		Description:    "OpenSourceOM workload package inventory",
		SourceSnapshot: snapshotLink,
		Type:           "zones/" + zone + "/diskTypes/pd-balanced",
		Labels:         scanLabels(vm),
	}
}

func attachedDisk(source, device string) *compute.AttachedDisk {
	return &compute.AttachedDisk{
		Source:     source,
		DeviceName: device,
		Mode:       "READ_ONLY",
		AutoDelete: false,
		Boot:       false,
	}
}

func scanLabels(vm string) map[string]string {
	return map[string]string{
		"opensourceom-scan":     "workload",
		"opensourceom-instance": labelValue(vm),
	}
}

func labelValue(vm string) string {
	if vm == "" || len(vm) > 63 {
		return "vm"
	}
	for _, r := range vm {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return "vm"
		}
	}
	return vm
}

func instanceFrom(zone string, inst *compute.Instance) (Instance, bool) {
	if inst == nil || inst.Name == "" {
		return Instance{}, false
	}
	item := Instance{Name: inst.Name, Zone: zone, Status: inst.Status}
	for _, disk := range inst.Disks {
		if disk == nil {
			continue
		}
		if disk.DeviceName != "" {
			item.Devices = append(item.Devices, disk.DeviceName)
		}
		if !disk.Boot {
			continue
		}
		item.BootSource = disk.Source
		item.Scratch = disk.Type == "SCRATCH" || disk.Source == ""
		item.Windows = windowsDisk(disk)
		item.CustomerKey = customerKey(disk.DiskEncryptionKey)
	}
	return item, true
}

func windowsDisk(disk *compute.AttachedDisk) bool {
	for _, feature := range disk.GuestOsFeatures {
		if feature != nil && strings.EqualFold(feature.Type, "WINDOWS") {
			return true
		}
	}
	for _, license := range disk.Licenses {
		if strings.Contains(strings.ToLower(license), "windows") {
			return true
		}
	}
	return false
}

func customerKey(key *compute.CustomerEncryptionKey) bool {
	if key == nil {
		return false
	}
	return key.RawKey != "" || key.RsaEncryptedKey != "" || key.Sha256 != ""
}

func diskRef(source string) (zonal bool, location, name string, err error) {
	parts := strings.Split(source, "/")
	var kind string
	for i := 0; i < len(parts)-1; i++ {
		switch parts[i] {
		case "zones":
			zonal = true
			kind = "zones"
			location = parts[i+1]
		case "regions":
			zonal = false
			kind = "regions"
			location = parts[i+1]
		case "disks":
			name = parts[i+1]
		}
	}
	if name == "" || location == "" || kind == "" {
		return false, "", "", fmt.Errorf("boot disk %s is not a zonal or regional persistent disk", source)
	}
	return zonal, location, name, nil
}

func operationError(op *compute.Operation) error {
	if op == nil || op.Error == nil || len(op.Error.Errors) == 0 || op.Error.Errors[0] == nil {
		return nil
	}
	msg := op.Error.Errors[0].Message
	if msg == "" {
		msg = op.HttpErrorMessage
	}
	if msg == "" {
		msg = "operation failed"
	}
	return errors.New(msg)
}

func objectName(vm string) string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return workload.SanitizeName(vm, strconv.FormatInt(time.Now().Unix(), 16), 63)
	}
	return workload.SanitizeName(vm, hex.EncodeToString(buf), 63)
}

func isGCPNotFound(err error) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == http.StatusNotFound
}
