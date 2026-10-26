// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

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
	findDevice func(ctx context.Context, lun string) (string, error)
}

// NewGuest mounts an attached Azure data disk read-only on this Linux VM.
func NewGuest() *guest {
	return &guest{findDevice: waitForLUN}
}

func (g *guest) MountReadOnly(ctx context.Context, lun string) (string, func() error, error) {
	return workload.MountReadOnly(ctx, lun, workload.MountFns{
		FindDevice: g.findDevice,
		Partitions: workload.ReadPartitions,
		IsLVM:      workload.DeviceIsLVM,
		Mount:      workload.MountFS,
		Unmount:    workload.Unmount,
		IsRoot:     workload.HasPackageDB,
	})
}

func waitForLUN(ctx context.Context, lun string) (string, error) {
	var last error
	for {
		path, err := lookupLUN(lun)
		if err == nil {
			return path, nil
		}
		last = err
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("lun %s did not appear on this VM: %w", lun, errors.Join(ctx.Err(), last))
		case <-timer.C:
		}
	}
}

func lookupLUN(lun string) (string, error) {
	var last error
	for _, path := range lunPaths(lun) {
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
		last = fmt.Errorf("no disk for lun %s", lun)
	}
	return "", last
}

func lunPaths(lun string) []string {
	name := "lun" + lun
	return []string{
		filepath.Join("/dev/disk/azure/scsi1", name),
		filepath.Join("/dev/disk/azure/data/by-lun", name),
	}
}
