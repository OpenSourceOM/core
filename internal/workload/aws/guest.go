// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
		partitions: readPartitions,
		isLVM:      deviceIsLVM,
		mount:      mountReadOnly,
		unmount:    unmount,
		isRoot:     workload.HasPackageDB,
	}
}

func (g *guest) MountReadOnly(ctx context.Context, volumeID string) (string, func() error, error) {
	disk, err := g.findDevice(ctx, volumeID)
	if err != nil {
		return "", nil, err
	}
	candidates := g.partitions(disk)
	if len(candidates) == 0 {
		candidates = []string{disk}
	}
	sawLVM := false
	var lastMount error
	for _, device := range candidates {
		if g.isLVM(device) {
			sawLVM = true
			continue
		}
		target, err := os.MkdirTemp("", "om-workload-")
		if err != nil {
			return "", nil, err
		}
		if err := g.mount(device, target); err != nil {
			os.RemoveAll(target)
			lastMount = err
			continue
		}
		if g.isRoot(target) {
			return target, func() error { return g.cleanup(target) }, nil
		}
		if err := g.cleanup(target); err != nil {
			return "", nil, err
		}
	}
	if lastMount != nil {
		return "", nil, lastMount
	}
	if sawLVM {
		return "", nil, workload.ErrLVM
	}
	return "", nil, workload.ErrNoPackages
}

func (g *guest) cleanup(target string) error {
	err := g.unmount(target)
	return errors.Join(err, os.RemoveAll(target))
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

func readPartitions(disk string) []string {
	base := filepath.Base(disk)
	entries, err := os.ReadDir(filepath.Join("/sys/block", base))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return partitionDevices(disk, names)
}

func partitionDevices(disk string, entries []string) []string {
	base := filepath.Base(disk)
	var out []string
	for _, name := range entries {
		if name != base && strings.HasPrefix(name, base) {
			out = append(out, filepath.Join("/dev", name))
		}
	}
	sort.Strings(out)
	return out
}

func deviceIsLVM(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, 512); err != nil {
		return false
	}
	return string(buf) == "LABELONE"
}

func mountReadOnly(device, target string) error {
	options := []string{
		"ro,noexec,nosuid,nodev",
		"ro,norecovery,noexec,nosuid,nodev",
	}
	var err error
	for _, opt := range options {
		cmd := exec.Command("mount", "-o", opt, device, target)
		out, runErr := cmd.CombinedOutput()
		if runErr == nil {
			return nil
		}
		err = fmt.Errorf("mount %s: %s", device, strings.TrimSpace(string(out)))
	}
	return err
}

func unmount(target string) error {
	cmd := exec.Command("umount", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %s", target, strings.TrimSpace(string(out)))
	}
	return nil
}
