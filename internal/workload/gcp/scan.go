// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
)

// Permissions are the IAM permissions om scan workload gcp adds.
// useToDecrypt is the unwrap a customer-managed key needs. useToEncrypt is the
// matching wrap when the snapshot keeps that key. om scan gcp does not gain these.
var Permissions = []string{
	"compute.instances.list",
	"compute.instances.get",
	"compute.disks.createSnapshot",
	"compute.regionDisks.createSnapshot",
	"compute.snapshots.create",
	"compute.snapshots.get",
	"compute.snapshots.delete",
	"compute.snapshots.useReadOnly",
	"compute.disks.create",
	"compute.disks.get",
	"compute.disks.delete",
	"compute.disks.useReadOnly",
	"compute.instances.attachDisk",
	"compute.instances.detachDisk",
	"compute.zoneOperations.get",
	"compute.globalOperations.get",
	"cloudkms.cryptoKeyVersions.useToDecrypt",
	"cloudkms.cryptoKeyVersions.useToEncrypt",
}

// Worker is the GCE instance the scan runs on.
type Worker struct {
	Name      string
	ProjectID string
	Zone      string
}

// Region is the worker zone without the trailing zone letter.
func (w Worker) Region() string { return regionOf(w.Zone) }

// Instance is one GCE instance in the worker's region.
type Instance struct {
	Name        string
	Zone        string
	Status      string
	Windows     bool
	BootSource  string
	SourceImage string
	Scratch     bool
	CustomerKey bool
	Devices     []string
}

// Result is one instance after the snapshot and disk are deleted.
type Result struct {
	Name     string
	Zone     string
	Packages []string
	Skipped  string
}

// API is the snapshot and disk lifecycle. Create calls wait until the resource
// is ready. A non-empty name is deleted even when create returns an error.
type API interface {
	List(ctx context.Context, region string) ([]Instance, error)
	CreateSnapshot(ctx context.Context, source, region, vm string) (string, error)
	DeleteSnapshot(ctx context.Context, name string) error
	CreateDisk(ctx context.Context, zone, snapshotName, vm string) (string, error)
	DeleteDisk(ctx context.Context, zone, name string) error
	Attach(ctx context.Context, zone, instance, diskName, device string) error
	Detach(ctx context.Context, zone, instance, device string) error
}

// Scanner snapshots Linux boot disks, reads them, and deletes what it created.
type Scanner struct {
	API     API
	Worker  Worker
	Only    []string
	Timeout time.Duration
	Mount   func(ctx context.Context, device string) (root string, cleanup func() error, err error)
	Walk    func(root string) ([]string, error)
	OnStart func(name, zone string)

	cleanupErrs []error
}

// Scan reads each Linux boot disk and calls write after that instance's
// snapshot and disk are deleted. A skip leaves packages unchanged.
func (s *Scanner) Scan(ctx context.Context, write func(Result) error) error {
	if s.Worker.Name == "" || s.Worker.Zone == "" {
		return fmt.Errorf("worker name and zone are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing a Compute client, mount, or package walker")
	}
	targets, worker, err := s.list(ctx)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	var failed []error
	for _, inst := range targets {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		res, scanErr := s.scanInstance(ictx, inst, worker.Devices)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", instLabel(res), err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *Scanner) list(ctx context.Context) ([]Instance, Instance, error) {
	instances, err := s.API.List(ctx, s.Worker.Region())
	if err != nil {
		return nil, Instance{}, err
	}
	worker, err := findInstance(instances, s.Worker.Zone+"/"+s.Worker.Name)
	if err != nil {
		return nil, Instance{}, fmt.Errorf("worker %s/%s is not in %s", s.Worker.Zone, s.Worker.Name, s.Worker.Region())
	}
	if len(s.Only) == 0 {
		return instances, worker, nil
	}
	var targets []Instance
	for _, want := range s.Only {
		inst, err := findInstance(instances, want)
		if err != nil {
			return nil, Instance{}, err
		}
		targets = append(targets, inst)
	}
	return targets, worker, nil
}

func (s *Scanner) scanInstance(ctx context.Context, inst Instance, devices []string) (Result, error) {
	res := Result{Name: inst.Name, Zone: inst.Zone}
	if skip := skipInstance(inst, s.Worker.Region()); skip != "" {
		res.Skipped = skip
		return res, nil
	}
	device := freeDevice(devices)
	if device == "" {
		return Result{}, fmt.Errorf("%s: no free device name on the worker", instLabel(res))
	}
	if s.OnStart != nil {
		s.OnStart(inst.Name, inst.Zone)
	}

	snap, err := s.API.CreateSnapshot(ctx, inst.BootSource, s.Worker.Region(), inst.Name)
	if snap != "" {
		defer s.deleteSnapshot(snap)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", instLabel(res), err)
	}
	disk, err := s.API.CreateDisk(ctx, s.Worker.Zone, snap, inst.Name)
	if disk != "" {
		defer s.deleteDisk(s.Worker.Zone, disk)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", instLabel(res), err)
	}
	if err := s.API.Attach(ctx, s.Worker.Zone, s.Worker.Name, disk, device); err != nil {
		return Result{}, fmt.Errorf("%s: %w", instLabel(res), err)
	}
	defer s.detach(s.Worker.Zone, device)

	root, unmount, err := s.Mount(ctx, device)
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", instLabel(res), err)
	}
	defer func() { s.note(unmount()) }()

	pkgs, err := s.Walk(root)
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", instLabel(res), err)
	}
	res.Packages = pkgs
	return res, nil
}

func (s *Scanner) detach(zone, device string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.Detach(ctx, zone, s.Worker.Name, device); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("detach disk %s: %w", device, err))
	}
}

func (s *Scanner) deleteDisk(zone, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.DeleteDisk(ctx, zone, name); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("delete disk %s: %w", name, err))
	}
}

func (s *Scanner) deleteSnapshot(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.API.DeleteSnapshot(ctx, name); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("delete snapshot %s: %w", name, err))
	}
}

func (s *Scanner) note(err error) {
	if err != nil {
		s.cleanupErrs = append(s.cleanupErrs, err)
	}
}

func skipInstance(inst Instance, region string) string {
	if regionOf(inst.Zone) != region {
		return "other region"
	}
	switch inst.Status {
	case "RUNNING", "TERMINATED":
	default:
		return "not running"
	}
	if inst.Windows {
		return "Windows"
	}
	if inst.CustomerKey {
		return "customer-supplied encryption key"
	}
	if inst.Scratch || inst.BootSource == "" {
		return "no persistent boot disk"
	}
	return ""
}

func freeDevice(used []string) string {
	taken := map[string]bool{}
	for _, name := range used {
		taken[name] = true
	}
	if !taken["omwl"] {
		return "omwl"
	}
	for letter := byte('b'); letter <= 'z'; letter++ {
		name := "omwl-" + string(letter)
		if !taken[name] {
			return name
		}
	}
	return ""
}

func findInstance(instances []Instance, want string) (Instance, error) {
	if strings.Contains(want, "/") {
		for _, inst := range instances {
			if inst.Zone+"/"+inst.Name == want {
				return inst, nil
			}
		}
		return Instance{}, fmt.Errorf("instance %s is not in this region", want)
	}
	var found []Instance
	for _, inst := range instances {
		if inst.Name == want {
			found = append(found, inst)
		}
	}
	if len(found) == 0 {
		return Instance{}, fmt.Errorf("instance %s is not in this region", want)
	}
	if len(found) > 1 {
		return Instance{}, fmt.Errorf("instance %s exists in more than one zone; pass zone/name", want)
	}
	return found[0], nil
}

func regionOf(zone string) string {
	zone = lastSegment(zone)
	i := strings.LastIndex(zone, "-")
	if i <= 0 {
		return zone
	}
	suffix := zone[i+1:]
	if len(suffix) == 1 && suffix[0] >= 'a' && suffix[0] <= 'z' {
		return zone[:i]
	}
	return zone
}

func lastSegment(path string) string {
	path = strings.TrimRight(path, "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func instLabel(res Result) string {
	if res.Zone == "" {
		return res.Name
	}
	return res.Zone + "/" + res.Name
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}
