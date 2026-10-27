// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

// Package version reports the build that is running.
//
// Release builds set version, commit, and date with -ldflags -X.
// A build without those flags uses the VCS metadata Go embeds, then "dev".
package version

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
)

const (
	Name       = "OpenSourceOM Core"
	repository = "https://github.com/OpenSourceOM/core"
)

// Set with -ldflags "-X github.com/OpenSourceOM/core/internal/version.version=0.5.0".
var (
	version = ""
	commit  = ""
	date    = ""
)

var (
	releaseVersion  = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?$`)
	pseudoVersion   = regexp.MustCompile(`^[0-9]{14}-[0-9a-f]+$`)
	pseudoTimestamp = regexp.MustCompile(`[0-9]{14}`)
)

// Build is the version a person can compare with a release, plus the commit
// that produced the binary.
type Build struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	CommitShort string `json:"commit_short"`
	Date        string `json:"date"`
	Modified    bool   `json:"modified"`
	CommitURL   string `json:"commit_url,omitempty"`
	ReleaseURL  string `json:"release_url,omitempty"`
}

// Current returns this process's build.
func Current() Build {
	moduleVersion := ""
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		moduleVersion = info.Main.Version
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
	}
	return resolve(version, commit, date, moduleVersion, settings)
}

func resolve(version, commit, date, moduleVersion string, settings map[string]string) Build {
	injectedCommit := strings.TrimSpace(commit) != ""
	version = strings.TrimSpace(version)
	if version == "" {
		candidate := strings.TrimSpace(moduleVersion)
		if candidate != "" && candidate != "(devel)" {
			version = candidate
		}
	}
	version = normalizeVersion(version)
	if version == "" {
		version = "dev"
	}

	commit = normalizeCommit(commit)
	if commit == "" {
		commit = normalizeCommit(settings["vcs.revision"])
	}
	if commit == "" {
		commit = "unknown"
	}

	date = strings.TrimSpace(date)
	if date == "" {
		date = strings.TrimSpace(settings["vcs.time"])
	}
	if date == "" {
		date = "unknown"
	}

	build := Build{
		Name:        Name,
		Version:     version,
		Commit:      commit,
		CommitShort: shortCommit(commit),
		Date:        date,
		Modified:    !injectedCommit && settings["vcs.modified"] == "true",
	}
	if url := commitURL(commit); url != "" {
		build.CommitURL = url
	}
	if url := releaseURL(version); url != "" {
		build.ReleaseURL = url
	}
	return build
}

func (b Build) String() string {
	commit := b.Commit
	if b.Modified && commit != "unknown" && !strings.HasSuffix(b.Version, "+dirty") {
		commit += " (modified)"
	}
	return fmt.Sprintf("%s %s\ncommit %s\ndate   %s", b.Name, b.Version, commit, b.Date)
}

func normalizeVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && (raw[0] == 'v' || raw[0] == 'V') && raw[1] >= '0' && raw[1] <= '9' {
		return raw[1:]
	}
	return raw
}

func normalizeCommit(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if isHex(raw) {
		return strings.ToLower(raw)
	}
	return raw
}

func shortCommit(commit string) string {
	if !isHex(commit) {
		return commit
	}
	if len(commit) > 7 {
		return commit[:7]
	}
	return commit
}

func commitURL(commit string) string {
	if !isHex(commit) || len(commit) < 7 {
		return ""
	}
	return repository + "/commit/" + commit
}

func releaseURL(version string) string {
	base, _, _ := strings.Cut(version, "+")
	if pseudoTimestamp.MatchString(base) {
		return ""
	}
	match := releaseVersion.FindStringSubmatch(base)
	if match == nil {
		return ""
	}
	if match[4] != "" && pseudoVersion.MatchString(match[4]) {
		return ""
	}
	return repository + "/releases/tag/v" + base
}

func isHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
