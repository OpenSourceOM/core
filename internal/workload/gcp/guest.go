// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
)

type guest struct {
	findDevice func(ctx context.Context, device string) (string, error)
}

// NewGuest mounts an attached persistent disk read-only on this Linux instance.
func NewGuest() *guest {
	return &guest{findDevice: waitForDevice}
}

func (g *guest) MountReadOnly(ctx context.Context, device string) (string, func() error, error) {
	return workload.MountReadOnly(ctx, device, workload.MountFns{
		FindDevice: g.findDevice,
		Partitions: workload.ReadPartitions,
		IsLVM:      workload.DeviceIsLVM,
		Mount:      workload.MountFS,
		Unmount:    workload.Unmount,
		IsRoot:     workload.HasPackageDB,
	})
}

func waitForDevice(ctx context.Context, device string) (string, error) {
	var last error
	for {
		path, err := lookupDevice(device)
		if err == nil {
			return path, nil
		}
		last = err
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("disk %s did not appear on this instance: %w", device, errors.Join(ctx.Err(), last))
		case <-timer.C:
		}
	}
}

func lookupDevice(device string) (string, error) {
	var last error
	for _, path := range devicePaths(device) {
		if _, err := os.Stat(path); err != nil {
			last = err
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}
	if last == nil {
		last = fmt.Errorf("no disk for %s", device)
	}
	return "", last
}

func devicePaths(device string) []string {
	return []string{
		filepath.Join("/dev/disk/by-id", "google-"+device),
		filepath.Join("/dev/disk/by-id", "scsi-0Google_PersistentDisk_"+device),
	}
}
