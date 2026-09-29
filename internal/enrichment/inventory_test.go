// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import "testing"

func TestParseInventory(t *testing.T) {
	inv := ParseInventory(map[string]any{
		"packages": []any{
			"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			"not-a-package",
			"pkg:maven/lodash",
		},
		"image":  "nginx:1.25.3",
		"images": []any{"nginx:1.25.3", "redis:7.2"},
	})
	if len(inv.Packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(inv.Packages))
	}
	if inv.Packages[0].Kind != kindCPE || inv.Packages[0].Vendor != "apache" || inv.Packages[0].Product != "log4j" || inv.Packages[0].Version != "2.14.1" {
		t.Fatalf("cpe = %+v", inv.Packages[0])
	}
	purl := inv.Packages[1]
	if purl.Kind != kindPURL || purl.Ecosystem != "maven" || purl.Namespace != "org.apache.logging.log4j" || purl.Name != "log4j-core" || purl.Version != "2.14.1" {
		t.Fatalf("purl = %+v", purl)
	}
	if len(inv.Images) != 2 || inv.Images[0] != "nginx:1.25.3" || inv.Images[1] != "redis:7.2" {
		t.Fatalf("images = %#v", inv.Images)
	}
	if !inv.HasCPE() {
		t.Fatal("expected a concrete CPE")
	}
}

func TestParseInventoryIgnoresWildcardCPE(t *testing.T) {
	inv := ParseInventory(map[string]any{
		"packages": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
	})
	if len(inv.Packages) != 1 {
		t.Fatalf("packages = %d", len(inv.Packages))
	}
	if inv.HasCPE() {
		t.Fatal("wildcard version is not a concrete CPE")
	}
}

func TestVersionCoversLog4ShellRange(t *testing.T) {
	in := func(v string) bool {
		return versionCovers(v, "*", "2.0", "", "2.14.1", "")
	}
	if !in("2.14.1") || !in("2.0") || !in("2.0.0") {
		t.Fatal("vulnerable versions should match")
	}
	if in("2.17.1") || in("1.2.17") || in("2.15.0") || in("latest") {
		t.Fatal("patched, older, and non-numeric versions should not match")
	}
}

func TestVersionCoversExact(t *testing.T) {
	if !versionCovers("2.14.1", "2.14.1", "", "", "", "") {
		t.Fatal("exact version should match")
	}
	if versionCovers("2.14.1", "2.14.0", "", "", "", "") {
		t.Fatal("different exact version should not match")
	}
	if versionCovers("2.14.1", "*", "", "", "", "") {
		t.Fatal("unbounded wildcard should not match")
	}
}

func TestCPESplitKeepsEscapedColon(t *testing.T) {
	fields := splitCPE(`cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*`)
	if len(fields) < 5 || fields[4] != "prod:uct" {
		t.Fatalf("fields = %#v", fields)
	}
}
