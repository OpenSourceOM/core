// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"strings"
	"unicode"
)

type osRelease struct {
	ID        string
	VersionID string
}

type software struct {
	ecosystem  string
	name       string
	version    string
	cpeVersion string
	epoch      string
	arch       string
}

func identifiers(osr osRelease, pkg software) []string {
	if pkg.name == "" || pkg.version == "" || pkg.cpeVersion == "" {
		return nil
	}
	ns := namespace(osr, pkg.ecosystem)
	cpe := "cpe:2.3:a:" + cpeEscape(strings.ToLower(pkg.name)) + ":" + cpeEscape(strings.ToLower(pkg.name)) + ":" + cpeEscape(pkg.cpeVersion) + ":*:*:*:*:*:*:*"
	purl := "pkg:" + pkg.ecosystem + "/" + purlEscape(ns) + "/" + purlEscape(pkg.name) + "@" + purlEscape(pkg.version)
	var query []string
	if pkg.arch != "" {
		query = append(query, "arch="+purlEscape(pkg.arch))
	}
	if distro := distroName(osr); distro != "" {
		query = append(query, "distro="+purlEscape(distro))
	}
	if pkg.epoch != "" && pkg.epoch != "0" {
		query = append(query, "epoch="+purlEscape(pkg.epoch))
	}
	if len(query) > 0 {
		purl += "?" + strings.Join(query, "&")
	}
	return []string{cpe, purl}
}

func namespace(osr osRelease, ecosystem string) string {
	if osr.ID != "" {
		return osr.ID
	}
	switch ecosystem {
	case "deb":
		return "debian"
	case "rpm":
		return "rhel"
	default:
		return "alpine"
	}
}

func distroName(osr osRelease) string {
	if osr.ID == "" {
		return ""
	}
	if osr.VersionID == "" {
		return osr.ID
	}
	return osr.ID + "-" + osr.VersionID
}

func cpeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', ':', '*', '?', '"', ' ':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func purlEscape(s string) string {
	return strings.NewReplacer(
		"%", "%25",
		"/", "%2F",
		"?", "%3F",
		"#", "%23",
		"@", "%40",
		" ", "%20",
	).Replace(s)
}

func splitDebVersion(v string) (epoch, upstream, full string) {
	full = v
	if i := strings.IndexByte(v, ':'); i > 0 && digits(v[:i]) {
		epoch = v[:i]
		full = v[i+1:]
	}
	upstream = full
	if i := strings.LastIndexByte(full, '-'); i > 0 {
		upstream = full[:i]
	}
	return epoch, upstream, full
}

func apkUpstream(v string) string {
	if i := strings.LastIndex(v, "-r"); i > 0 && digits(v[i+2:]) {
		return v[:i]
	}
	return v
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
