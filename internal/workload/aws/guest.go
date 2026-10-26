// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
)

type guest struct {
	findDevice func(ctx context.Context, volumeID string) (string, error)
	partitions func(disk string) []string
	isLVM      func(device string) bool
	mount      func(device, target string) error
	unmount    func(target string) error
	isRoot     func(target string) bool
}

// NewGuest mounts an attached EBS volume read-only on this Linux instance.
func NewGuest() *guest {
	return &guest{
		findDevice: waitForDisk,
		partitions: workload.ReadPartitions,
		isLVM:      workload.DeviceIsLVM,
		mount:      workload.MountFS,
		unmount:    workload.Unmount,
		isRoot:     workload.HasPackageDB,
	}
}

func (g *guest) MountReadOnly(ctx context.Context, volumeID string) (string, func() error, error) {
	return workload.MountReadOnly(ctx, volumeID, workload.MountFns{
		FindDevice: g.findDevice,
		Partitions: g.partitions,
		IsLVM:      g.isLVM,
		Mount:      g.mount,
		Unmount:    g.unmount,
		IsRoot:     g.isRoot,
	})
}

func waitForDisk(ctx context.Context, volumeID string) (string, error) {
	var last error
	for {
		path, err := lookupDisk(volumeID)
		if err == nil {
			return path, nil
		}
		last = err
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("volume %s did not appear on this instance: %w", volumeID, errors.Join(ctx.Err(), last))
		case <-timer.C:
		}
	}
}

func lookupDisk(volumeID string) (string, error) {
	entries, err := os.ReadDir("/dev/disk/by-id")
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	name := diskByID(names, volumeID)
	if name == "" {
		return "", fmt.Errorf("no disk for %s", volumeID)
	}
	return filepath.EvalSymlinks(filepath.Join("/dev/disk/by-id", name))
}

func diskByID(names []string, volumeID string) string {
	serial := strings.ReplaceAll(volumeID, "-", "")
	for _, name := range names {
		if !volumeNameMatches(name, serial) {
			continue
		}
		return name
	}
	return ""
}

func volumeNameMatches(name, serial string) bool {
	if strings.Contains(name, "-part") {
		return false
	}
	i := strings.Index(name, serial)
	if i < 0 {
		return false
	}
	end := i + len(serial)
	if end < len(name) && isHex(name[end]) {
		return false
	}
	return true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
