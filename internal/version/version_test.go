// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"strings"
	"testing"
)

func TestResolveReleaseBuild(t *testing.T) {
	got := resolve("v0.5.0", "ABCDEF1234567890", "2026-10-26T22:00:00Z", "(devel)", map[string]string{
		"vcs.revision": "ffffffffffffffff",
		"vcs.modified": "true",
		"vcs.time":     "2020-01-01T00:00:00Z",
	})
	if got.Name != Name || got.Version != "0.5.0" {
		t.Fatalf("name/version = %s %s", got.Name, got.Version)
	}
	if got.Commit != "abcdef1234567890" || got.CommitShort != "abcdef1" {
		t.Fatalf("commit = %s %s", got.Commit, got.CommitShort)
	}
	if got.Date != "2026-10-26T22:00:00Z" {
		t.Fatalf("date = %s", got.Date)
	}
	if got.Modified {
		t.Fatal("an injected commit must not inherit a dirty workspace")
	}
	if got.CommitURL != "https://github.com/OpenSourceOM/core/commit/abcdef1234567890" {
		t.Fatalf("commit url = %s", got.CommitURL)
	}
	if got.ReleaseURL != "https://github.com/OpenSourceOM/core/releases/tag/v0.5.0" {
		t.Fatalf("release url = %s", got.ReleaseURL)
	}
	text := got.String()
	if !strings.Contains(text, "OpenSourceOM Core 0.5.0") || !strings.Contains(text, "commit abcdef1234567890") {
		t.Fatalf("string = %q", text)
	}
}

func TestResolveSourceBuildUsesVCS(t *testing.T) {
	got := resolve("", "", "", "(devel)", map[string]string{
		"vcs.revision": "abc1234def5678",
		"vcs.modified": "true",
		"vcs.time":     "2026-10-26T22:00:00Z",
	})
	if got.Version != "dev" {
		t.Fatalf("version = %s", got.Version)
	}
	if got.Commit != "abc1234def5678" || !got.Modified {
		t.Fatalf("commit = %+v", got)
	}
	if got.ReleaseURL != "" {
		t.Fatalf("dev build advertised a release: %s", got.ReleaseURL)
	}
	if !strings.Contains(got.String(), "abc1234def5678 (modified)") {
		t.Fatalf("string = %q", got.String())
	}
}

func TestResolveModuleVersionAndPseudoVersion(t *testing.T) {
	release := resolve("", "", "", "v0.5.0", nil)
	if release.Version != "0.5.0" || release.ReleaseURL == "" {
		t.Fatalf("module version = %+v", release)
	}
	pseudo := resolve("", "", "", "v0.0.0-20261026120000-abcdef123456", nil)
	if pseudo.Version != "0.0.0-20261026120000-abcdef123456" {
		t.Fatalf("version = %s", pseudo.Version)
	}
	if pseudo.ReleaseURL != "" {
		t.Fatalf("pseudo-version advertised a release: %s", pseudo.ReleaseURL)
	}
	if pseudo.Commit != "unknown" || pseudo.Date != "unknown" {
		t.Fatalf("missing vcs = %+v", pseudo)
	}
}

func TestResolveTaggedCheckout(t *testing.T) {
	got := resolve("", "", "", "v0.5.0+dirty", map[string]string{
		"vcs.revision": "abc1234def5678",
		"vcs.modified": "true",
		"vcs.time":     "2026-10-26T22:00:00Z",
	})
	if got.Version != "0.5.0+dirty" || !got.Modified {
		t.Fatalf("%+v", got)
	}
	if got.ReleaseURL != "https://github.com/OpenSourceOM/core/releases/tag/v0.5.0" {
		t.Fatalf("release url = %s", got.ReleaseURL)
	}
	if strings.Contains(got.String(), "(modified)") {
		t.Fatalf("dirty version was repeated on the commit: %q", got.String())
	}
}

func TestResolveRejectsUnreleasedVersions(t *testing.T) {
	for _, version := range []string{"dev", "nightly", "1", "0.5", "v1.2", "0.5.1-0.20261027120000-abcdef123456"} {
		if got := releaseURL(normalizeVersion(version)); got != "" {
			t.Fatalf("version %s linked to %s", version, got)
		}
	}
	if got := releaseURL("0.5.0-rc.1"); got != "https://github.com/OpenSourceOM/core/releases/tag/v0.5.0-rc.1" {
		t.Fatalf("prerelease url = %s", got)
	}
	if got := releaseURL("0.5.0+dirty"); got != "https://github.com/OpenSourceOM/core/releases/tag/v0.5.0" {
		t.Fatalf("dirty release url = %s", got)
	}
	if commitURL("unknown") != "" || commitURL("abc") != "" || shortCommit("unknown") != "unknown" {
		t.Fatal("non-commits should stay plain text")
	}
}

func TestCurrentReportsAVersion(t *testing.T) {
	got := Current()
	if got.Name != Name || got.Version == "" || got.Commit == "" || got.CommitShort == "" || got.Date == "" {
		t.Fatalf("%+v", got)
	}
}
