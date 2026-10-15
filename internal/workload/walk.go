// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxPackageDBBytes = 256 << 20

// packageDBPaths are the package databases Walk reads. File contents elsewhere
// on the filesystem are left unread.
var packageDBPaths = []string{
	"var/lib/dpkg/status",
	"lib/apk/db/installed",
	"usr/lib/apk/db/installed",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db",
	"var/lib/rpm/Packages.db",
	"var/lib/rpm/Packages",
}

// HasPackageDB reports whether root contains a dpkg, apk, or rpm database.
func HasPackageDB(root string) bool {
	for _, rel := range packageDBPaths {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			return true
		}
	}
	return false
}

// Walk reads package databases under root and returns CPE 2.3 names and
// versioned package URLs. It does not return file contents.
func Walk(root string) ([]string, error) {
	osr := readOSRelease(root)
	var (
		found bool
		pkgs  []software
	)
	for _, read := range []func(string) ([]software, bool, error){readDeb, readAPK, readRPM} {
		list, ok, err := read(root)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		found = true
		pkgs = append(pkgs, list...)
	}
	if !found {
		return nil, ErrNoPackages
	}
	seen := map[string]struct{}{}
	var ids []string
	for _, pkg := range pkgs {
		for _, id := range identifiers(osr, pkg) {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func readOSRelease(root string) osRelease {
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		osr := parseOSRelease(f)
		f.Close()
		return osr
	}
	return osRelease{}
}

func parseOSRelease(r io.Reader) osRelease {
	var osr osRelease
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "ID":
			osr.ID = strings.ToLower(value)
		case "VERSION_ID":
			osr.VersionID = value
		}
	}
	return osr
}

func readDeb(root string) ([]software, bool, error) {
	path := filepath.Join(root, "var/lib/dpkg/status")
	f, err := openDB(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read dpkg status: %w", err)
	}
	defer f.Close()
	return parseDeb(f), true, nil
}

func parseDeb(r io.Reader) []software {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var fields map[string]string
	var out []software
	flush := func() {
		if fields == nil {
			return
		}
		name := fields["Package"]
		version := fields["Version"]
		if name != "" && version != "" && debInstalled(fields["Status"]) {
			epoch, upstream, full := splitDebVersion(version)
			out = append(out, software{
				ecosystem:  "deb",
				name:       name,
				version:    full,
				cpeVersion: upstream,
				epoch:      epoch,
				arch:       fields["Architecture"],
			})
		}
		fields = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if fields == nil {
			fields = map[string]string{}
		}
		fields[key] = value
	}
	flush()
	return out
}

func debInstalled(status string) bool {
	parts := strings.Fields(status)
	return len(parts) == 3 && parts[2] == "installed"
}

func readAPK(root string) ([]software, bool, error) {
	for _, rel := range []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"} {
		f, err := openDB(filepath.Join(root, rel))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("read apk database: %w", err)
		}
		pkgs := parseAPK(f)
		f.Close()
		return pkgs, true, nil
	}
	return nil, false, nil
}

func parseAPK(r io.Reader) []software {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var name, version, arch string
	var out []software
	flush := func() {
		if name != "" && version != "" {
			out = append(out, software{
				ecosystem:  "apk",
				name:       name,
				version:    version,
				cpeVersion: apkUpstream(version),
				arch:       arch,
			})
		}
		name, version, arch = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			name = value
		case "V":
			version = value
		case "A":
			arch = value
		}
	}
	flush()
	return out
}

func openDB(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > maxPackageDBBytes {
		f.Close()
		return nil, fmt.Errorf("%s is %d bytes", filepath.Base(path), info.Size())
	}
	return f, nil
}
