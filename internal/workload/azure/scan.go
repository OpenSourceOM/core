// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
)

// Permissions are the Azure RBAC actions om scan workload azure adds.
// keys/unwrap/action and keys/wrap/action are the grant a customer-managed key needs.
// om scan azure does not gain these actions.
var Permissions = []string{
	"Microsoft.Compute/virtualMachines/read",
	"Microsoft.Compute/disks/read",
	"Microsoft.Compute/disks/beginGetAccess/action",
	"Microsoft.Compute/snapshots/read",
	"Microsoft.Compute/snapshots/write",
	"Microsoft.Compute/snapshots/delete",
	"Microsoft.Compute/disks/write",
	"Microsoft.Compute/disks/delete",
	"Microsoft.Compute/virtualMachines/attachDetachDataDisks/action",
	"Microsoft.Compute/diskEncryptionSets/read",
	"Microsoft.KeyVault/vaults/keys/wrap/action",
	"Microsoft.KeyVault/vaults/keys/unwrap/action",
}

// Worker is the Azure VM the scan runs on.
type Worker struct {
	Name           string
	ResourceGroup  string
	SubscriptionID string
	Location       string
	Zone           string
}

// Machine is one virtual machine in the worker's location.
type Machine struct {
	Name              string
	ResourceGroup     string
	Location          string
	ID                string
	OS                string
	OSDiskID          string
	Ephemeral         bool
	ProvisioningState string
	DataLUNs          []int32
}

// Result is one VM after the snapshot and disk are deleted.
type Result struct {
	Name          string
	ResourceGroup string
	Packages      []string
	Skipped       string
}

// API is the snapshot and disk lifecycle. Create calls wait until the resource
// is ready. A non-empty name is deleted even when create returns an error.
type API interface {
	List(ctx context.Context, location string) ([]Machine, error)
	CreateSnapshot(ctx context.Context, group, location, sourceDisk, vm string) (string, error)
	DeleteSnapshot(ctx context.Context, group, name string) error
	CreateDisk(ctx context.Context, group, location, snapshotName string, zones []string, vm string) (string, error)
	DeleteDisk(ctx context.Context, group, name string) error
	Attach(ctx context.Context, group, vm, diskName string, lun int32) error
	Detach(ctx context.Context, group, vm, diskName string) error
}

// Scanner snapshots Linux OS disks, reads them, and deletes what it created.
type Scanner struct {
	API     API
	Worker  Worker
	Only    []string
	Timeout time.Duration
	Mount   func(ctx context.Context, lun string) (root string, cleanup func() error, err error)
	Walk    func(root string) ([]string, error)
	OnStart func(name, group string)

	cleanupErrs []error
}

// Scan reads each Linux OS disk and calls write after that VM's snapshot and
// disk are deleted. A skip leaves packages unchanged.
func (s *Scanner) Scan(ctx context.Context, write func(Result) error) error {
	if s.Worker.Name == "" || s.Worker.ResourceGroup == "" || s.Worker.Location == "" {
		return fmt.Errorf("worker name, resource group, and location are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing an Azure client, mount, or package walker")
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
	for _, vm := range targets {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		res, scanErr := s.scanVM(ictx, vm, worker.DataLUNs)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", vmLabel(res), err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *Scanner) list(ctx context.Context) ([]Machine, Machine, error) {
	machines, err := s.API.List(ctx, normalizeLocation(s.Worker.Location))
	if err != nil {
		return nil, Machine{}, err
	}
	worker, err := findMachine(machines, s.Worker.ResourceGroup+"/"+s.Worker.Name)
	if err != nil {
		return nil, Machine{}, fmt.Errorf("worker %s/%s is not in %s", s.Worker.ResourceGroup, s.Worker.Name, normalizeLocation(s.Worker.Location))
	}
	if len(s.Only) == 0 {
		return machines, worker, nil
	}
	var targets []Machine
	for _, want := range s.Only {
		vm, err := findMachine(machines, want)
		if err != nil {
			return nil, Machine{}, err
		}
		targets = append(targets, vm)
	}
	return targets, worker, nil
}

func (s *Scanner) scanVM(ctx context.Context, vm Machine, luns []int32) (Result, error) {
	res := Result{Name: vm.Name, ResourceGroup: vm.ResourceGroup}
	if skip := skipMachine(vm, s.Worker.Location); skip != "" {
		res.Skipped = skip
		return res, nil
	}
	lun, ok := freeLUN(luns)
	if !ok {
		return Result{}, fmt.Errorf("%s: no free LUN on the worker", vmLabel(res))
	}
	if s.OnStart != nil {
		s.OnStart(vm.Name, vm.ResourceGroup)
	}

	group := s.Worker.ResourceGroup
	snap, err := s.API.CreateSnapshot(ctx, group, normalizeLocation(s.Worker.Location), vm.OSDiskID, vm.Name)
	if snap != "" {
		defer s.deleteSnapshot(group, snap)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", vmLabel(res), err)
	}
	disk, err := s.API.CreateDisk(ctx, group, normalizeLocation(s.Worker.Location), snap, s.Worker.zones(), vm.Name)
	if disk != "" {
		defer s.deleteDisk(group, disk)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", vmLabel(res), err)
	}
	if err := s.API.Attach(ctx, group, s.Worker.Name, disk, lun); err != nil {
		return Result{}, fmt.Errorf("%s: %w", vmLabel(res), err)
	}
	defer s.detach(group, disk)

	root, unmount, err := s.Mount(ctx, fmt.Sprintf("%d", lun))
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", vmLabel(res), err)
	}
	defer func() { s.note(unmount()) }()

	pkgs, err := s.Walk(root)
	if err != nil {
		if reason, ok := workload.Reason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", vmLabel(res), err)
	}
	res.Packages = pkgs
	return res, nil
}

func (w Worker) zones() []string {
	if w.Zone == "" {
		return nil
	}
	return []string{w.Zone}
}

func (s *Scanner) detach(group, disk string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.Detach(ctx, group, s.Worker.Name, disk); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("detach disk %s: %w", disk, err))
	}
}

func (s *Scanner) deleteDisk(group, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.API.DeleteDisk(ctx, group, name); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("delete disk %s: %w", name, err))
	}
}

func (s *Scanner) deleteSnapshot(group, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.API.DeleteSnapshot(ctx, group, name); err != nil && !isNotFound(err) {
		s.note(fmt.Errorf("delete snapshot %s: %w", name, err))
	}
}

func (s *Scanner) note(err error) {
	if err != nil {
		s.cleanupErrs = append(s.cleanupErrs, err)
	}
}

func skipMachine(vm Machine, workerLocation string) string {
	if !sameLocation(vm.Location, workerLocation) {
		return "other region"
	}
	if vm.ProvisioningState != "" && !strings.EqualFold(vm.ProvisioningState, "Succeeded") {
		return "not ready"
	}
	if vm.OS == "windows" {
		return "Windows"
	}
	if vm.Ephemeral {
		return "ephemeral OS disk"
	}
	if vm.OSDiskID == "" {
		return "no managed OS disk"
	}
	return ""
}

func freeLUN(used []int32) (int32, bool) {
	taken := map[int32]bool{}
	for _, n := range used {
		taken[n] = true
	}
	for n := int32(0); n < 16; n++ {
		if !taken[n] {
			return n, true
		}
	}
	return 0, false
}

func findMachine(machines []Machine, want string) (Machine, error) {
	if strings.Contains(want, "/") {
		for _, vm := range machines {
			if strings.EqualFold(vm.ID, want) || strings.EqualFold(vm.ResourceGroup+"/"+vm.Name, want) {
				return vm, nil
			}
		}
		return Machine{}, fmt.Errorf("virtual machine %s is not in this region", want)
	}
	var found []Machine
	for _, vm := range machines {
		if strings.EqualFold(vm.Name, want) {
			found = append(found, vm)
		}
	}
	if len(found) == 0 {
		return Machine{}, fmt.Errorf("virtual machine %s is not in this region", want)
	}
	if len(found) > 1 {
		return Machine{}, fmt.Errorf("virtual machine %s exists in more than one resource group; pass resource group/name", want)
	}
	return found[0], nil
}

func normalizeLocation(location string) string {
	return strings.ToLower(strings.ReplaceAll(location, " ", ""))
}

func sameLocation(a, b string) bool {
	return normalizeLocation(a) == normalizeLocation(b)
}

func vmLabel(res Result) string {
	if res.ResourceGroup == "" {
		return res.Name
	}
	return res.ResourceGroup + "/" + res.Name
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}
