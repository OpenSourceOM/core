// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// MountFns finds a block device and mounts a partition read-only.
type MountFns struct {
	FindDevice func(ctx context.Context, id string) (string, error)
	Partitions func(disk string) []string
	IsLVM      func(device string) bool
	Mount      func(device, target string) error
	Unmount    func(target string) error
	IsRoot     func(target string) bool
}

// MountReadOnly mounts the first partition that has a package database.
// An LVM physical volume is left unmounted.
func MountReadOnly(ctx context.Context, id string, fns MountFns) (string, func() error, error) {
	if fns.FindDevice == nil || fns.Mount == nil || fns.Unmount == nil || fns.IsRoot == nil {
		return "", nil, fmt.Errorf("workload mount is incomplete")
	}
	disk, err := fns.FindDevice(ctx, id)
	if err != nil {
		return "", nil, err
	}
	candidates := []string{disk}
	if fns.Partitions != nil {
		if parts := fns.Partitions(disk); len(parts) > 0 {
			candidates = parts
		}
	}
	isLVM := fns.IsLVM
	if isLVM == nil {
		isLVM = func(string) bool { return false }
	}
	sawLVM := false
	var lastMount error
	for _, device := range candidates {
		if isLVM(device) {
			sawLVM = true
			continue
		}
		target, err := os.MkdirTemp("", "om-workload-")
		if err != nil {
			return "", nil, err
		}
		if err := fns.Mount(device, target); err != nil {
			os.RemoveAll(target)
			lastMount = err
			continue
		}
		if fns.IsRoot(target) {
			return target, func() error { return cleanupMount(target, fns.Unmount) }, nil
		}
		if err := cleanupMount(target, fns.Unmount); err != nil {
			return "", nil, err
		}
	}
	if lastMount != nil {
		return "", nil, lastMount
	}
	if sawLVM {
		return "", nil, ErrLVM
	}
	return "", nil, ErrNoPackages
}

func cleanupMount(target string, unmount func(string) error) error {
	return errors.Join(unmount(target), os.RemoveAll(target))
}

// ReadPartitions lists partition device paths for a whole disk.
func ReadPartitions(disk string) []string {
	base := filepath.Base(disk)
	entries, err := os.ReadDir(filepath.Join("/sys/block", base))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return PartitionDevices(disk, names)
}

// PartitionDevices keeps sysfs entries that are partitions of disk.
func PartitionDevices(disk string, entries []string) []string {
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

// DeviceIsLVM reports whether the device starts with an LVM physical-volume label.
func DeviceIsLVM(path string) bool {
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

// MountFS mounts device on target read-only, without executing files on it.
func MountFS(device, target string) error {
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

// Unmount detaches a filesystem mounted by MountFS.
func Unmount(target string) error {
	cmd := exec.Command("umount", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %s", target, strings.TrimSpace(string(out)))
	}
	return nil
}

// SanitizeName builds a cloud resource name from a workload name and a suffix.
func SanitizeName(vm, suffix string, max int) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(vm) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !ok {
			r = '-'
		}
		if r == '-' {
			if prevDash || b.Len() == 0 {
				continue
			}
			prevDash = true
			b.WriteRune(r)
			continue
		}
		prevDash = false
		b.WriteRune(r)
	}
	clean := strings.TrimRight(b.String(), "-")
	if clean == "" {
		clean = "vm"
	}
	const prefix = "omwl-"
	tail := "-" + suffix
	room := max - len(prefix) - len(tail)
	if room < 1 {
		clean = "vm"
	} else if len(clean) > room {
		clean = strings.TrimRight(clean[:room], "-")
		if clean == "" {
			clean = "vm"
		}
	}
	return prefix + clean + tail
}
