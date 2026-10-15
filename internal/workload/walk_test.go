// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/enrichment"
)

func TestWalkDeb(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=ubuntu\nVERSION_ID=\"22.04\"\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), `
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 1.1.1n-0ubuntu1
Description: library
 BEGIN PRIVATE KEY

Package: bash
Status: install ok installed
Architecture: amd64
Version: 1:2.0.5-1

Package: old
Status: deinstall ok config-files
Architecture: all
Version: 1.0

Package: empty
Status: install ok installed
Architecture: amd64
Version:
`)
	writeFile(t, filepath.Join(root, "home/app/notes.txt"), "AKIAIOSFODNN7EXAMPLE")

	ids, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ids, "\n")
	for _, forbidden := range []string{"PRIVATE KEY", "AKIAIOSFODNN7EXAMPLE", "library"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("identifier list contains %q\n%s", forbidden, joined)
		}
	}
	want := []string{
		"cpe:2.3:a:bash:bash:2.0.5:*:*:*:*:*:*:*",
		"cpe:2.3:a:openssl:openssl:1.1.1n:*:*:*:*:*:*:*",
		"pkg:deb/ubuntu/bash@2.0.5-1?arch=amd64&distro=ubuntu-22.04&epoch=1",
		"pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1?arch=amd64&distro=ubuntu-22.04",
	}
	if strings.Join(ids, "\n") != strings.Join(want, "\n") {
		t.Fatalf("packages =\n%s\nwant\n%s", strings.Join(ids, "\n"), strings.Join(want, "\n"))
	}
	assertParsed(t, ids)
}

func TestWalkAPK(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=alpine\nVERSION_ID=3.19\n")
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `
P:openssl
V:3.1.4-r0
A:x86_64

P:busybox
V:1.36.1-r15
A:x86_64
`)
	ids, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:openssl:openssl:3.1.4:*:*:*:*:*:*:*",
		"pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.19",
		"pkg:apk/alpine/openssl@3.1.4-r0?arch=x86_64&distro=alpine-3.19",
	}
	if strings.Join(ids, "\n") != strings.Join(want, "\n") {
		t.Fatalf("packages =\n%s\nwant\n%s", strings.Join(ids, "\n"), strings.Join(want, "\n"))
	}
	assertParsed(t, ids)
}

func TestWalkRPM(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=amzn\nVERSION_ID=\"2023\"\n")
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/sysimage/rpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeSQLiteRPMDB(t, filepath.Join(root, "usr/lib/sysimage/rpm/rpmdb.sqlite"))

	ids, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ids, "\n")
	if strings.Contains(joined, "gpg-pubkey") {
		t.Fatalf("gpg-pubkey was stored:\n%s", joined)
	}
	want := []string{
		"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
		"pkg:rpm/amzn/openssl@1.1.1k-7.amzn2023?arch=x86_64&distro=amzn-2023",
	}
	if joined != strings.Join(want, "\n") {
		t.Fatalf("packages =\n%s\nwant\n%s", joined, strings.Join(want, "\n"))
	}
	assertParsed(t, ids)
}

func TestWalkMissingDatabase(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=ubuntu\n")
	writeFile(t, filepath.Join(root, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n")
	_, err := Walk(root)
	if err != ErrNoPackages {
		t.Fatalf("err = %v", err)
	}
}

func TestCPEEscape(t *testing.T) {
	got := identifiers(osRelease{ID: "debian"}, software{
		ecosystem: "deb", name: "weird", version: "1.0:2", cpeVersion: "1.0:2",
	})
	if len(got) != 2 || !strings.Contains(got[0], `1.0\:2`) {
		t.Fatalf("ids = %#v", got)
	}
	assertParsed(t, got)
}

func assertParsed(t *testing.T, ids []string) {
	t.Helper()
	raw := make([]any, len(ids))
	for i, id := range ids {
		raw[i] = id
	}
	inv := enrichment.ParseInventory(map[string]any{"packages": raw})
	if len(inv.Packages) != len(ids) {
		t.Fatalf("parsed %d of %d: %#v", len(inv.Packages), len(ids), ids)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeSQLiteRPMDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO Packages (hnum, blob) VALUES (1, ?), (2, ?)`,
		rpmHeader("openssl", "1.1.1k", "7.amzn2023", "x86_64"),
		rpmHeader("gpg-pubkey", "abcd", "1234", "x86_64"),
	); err != nil {
		t.Fatal(err)
	}
}

func rpmHeader(name, version, release, arch string) []byte {
	fields := []struct {
		tag uint32
		val string
	}{
		{1000, name},
		{1001, version},
		{1002, release},
		{1022, arch},
	}
	var data []byte
	var entries [][4]uint32
	for _, field := range fields {
		entries = append(entries, [4]uint32{field.tag, 6, uint32(len(data)), 1})
		data = append(data, append([]byte(field.val), 0)...)
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	for _, entry := range entries {
		for _, v := range entry {
			b = binary.BigEndian.AppendUint32(b, v)
		}
	}
	return append(b, data...)
}
