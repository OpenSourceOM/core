// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import "errors"

// Reason returns a skip message when err leaves the workload's packages unchanged.
func Reason(err error) (string, bool) {
	var reason interface{ SkipReason() string }
	if err != nil && errors.As(err, &reason) {
		return reason.SkipReason(), true
	}
	return "", false
}

// Skip is a condition that leaves the workload's packages unchanged.
type Skip string

func (s Skip) Error() string { return string(s) }

func (s Skip) SkipReason() string { return string(s) }

const (
	// ErrNoPackages means the root filesystem has no dpkg, apk, or rpm database.
	ErrNoPackages Skip = "no package database"
	// ErrLVM means the root volume is an LVM physical volume.
	ErrLVM Skip = "LVM root volumes are not scanned"
	// ErrImageDenied means the account cannot copy this boot image.
	// Marketplace and shared images the account is not allowed to snapshot use it.
	ErrImageDenied Skip = "account cannot snapshot this image"
)
