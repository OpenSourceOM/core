// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	// Pure-Go SQLite driver used to open rpmdb.sqlite.
	_ "github.com/glebarez/go-sqlite"
)

var rpmDBPaths = []string{
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db",
	"var/lib/rpm/Packages.db",
	"var/lib/rpm/Packages",
}

func readRPM(root string) ([]software, bool, error) {
	for _, rel := range rpmDBPaths {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("read rpm database: %w", err)
		}
		if info.Size() > maxPackageDBBytes {
			return nil, false, fmt.Errorf("%s is %d bytes", filepath.Base(path), info.Size())
		}
		db, err := rpmdb.Open(path)
		if err != nil {
			return nil, false, fmt.Errorf("read rpm database: %w", err)
		}
		// The database lists installed files. Only the name and version are kept.
		list, err := db.ListPackages()
		db.Close()
		if err != nil {
			return nil, false, fmt.Errorf("read rpm database: %w", err)
		}
		var out []software
		for _, pkg := range list {
			if pkg == nil || pkg.Name == "" || pkg.Name == "gpg-pubkey" || pkg.Version == "" {
				continue
			}
			version := pkg.Version
			if pkg.Release != "" {
				version += "-" + pkg.Release
			}
			sw := software{
				ecosystem:  "rpm",
				name:       pkg.Name,
				version:    version,
				cpeVersion: pkg.Version,
				arch:       pkg.Arch,
			}
			if pkg.Epoch != nil && *pkg.Epoch > 0 {
				sw.epoch = strconv.Itoa(*pkg.Epoch)
			}
			out = append(out, sw)
		}
		return out, true, nil
	}
	return nil, false, nil
}
