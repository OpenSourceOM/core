// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package enrichment

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceOM/core/internal/enrichment/nvd"
)

func TestSelectCVEsKeepsRangeMatch(t *testing.T) {
	inv := ParseInventory(map[string]any{
		"packages": []any{
			"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		},
	})
	cves := []nvd.CVE{{
		ID: "CVE-2021-44228", Severity: "critical", Normalized: 95, CVSSScore: 10,
		Matches: []nvd.CPEMatch{{
			Part: "a", Vendor: "apache", Product: "log4j", Version: "*",
			VersionStartIncluding: "2.0", VersionEndIncluding: "2.14.1",
		}},
	}}
	got := selectCVEs(inv, cves)
	if len(got) != 1 || got[0].Matched != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Fatalf("hits = %+v", got)
	}

	patched := ParseInventory(map[string]any{
		"packages": []any{"cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"},
	})
	if hits := selectCVEs(patched, cves); len(hits) != 0 {
		t.Fatalf("patched hits = %+v", hits)
	}
}

func TestCatalogMatchesDemoPackagesAndImages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	body := []byte(`{
	  "cves": [
	    {
	      "id": "CVE-2021-44228",
	      "description": "Apache Log4j2 2.0 through 2.14.1 JNDI features do not protect against attacker-controlled LDAP.",
	      "cvss_score": 10,
	      "packages": [
	        {
	          "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
	          "version_start_including": "2.0",
	          "version_end_including": "2.14.1"
	        },
	        {
	          "ecosystem": "maven",
	          "namespace": "org.apache.logging.log4j",
	          "name": "log4j-core",
	          "version_start_including": "2.0",
	          "version_end_including": "2.14.1"
	        }
	      ]
	    },
	    {
	      "id": "CVE-2024-0001",
	      "description": "Sample image finding.",
	      "cvss_score": 7.5,
	      "images": ["nginx:1.25.3"]
	    }
	  ]
	}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := loadCatalog(path)
	if err != nil {
		t.Fatal(err)
	}

	web := ParseInventory(map[string]any{
		"packages": []any{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
	})
	hits, err := src.Match(context.Background(), web, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2021-44228" || hits[0].Severity != "critical" {
		t.Fatalf("web hits = %+v", hits)
	}

	worker := ParseInventory(map[string]any{
		"packages": []any{"cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"},
	})
	hits, err = src.Match(context.Background(), worker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("worker hits = %+v", hits)
	}

	purl := ParseInventory(map[string]any{
		"packages": []any{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
	})
	hits, err = src.Match(context.Background(), purl, []string{"cve-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Matched != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Fatalf("purl hits = %+v", hits)
	}

	image := ParseInventory(map[string]any{"image": "nginx:1.25.3"})
	hits, err = src.Match(context.Background(), image, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2024-0001" || hits[0].Matched != "nginx:1.25.3" {
		t.Fatalf("image hits = %+v", hits)
	}

	_, err = src.Match(context.Background(), web, []string{"CVE-1999-0001"})
	if err == nil {
		t.Fatal("missing catalog id should fail")
	}
}

func TestExampleCatalogMatchesDemoWeb(t *testing.T) {
	src, err := loadCatalog("../../examples/cve-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	web := ParseInventory(map[string]any{
		"packages": []any{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
	})
	hits, err := src.Match(context.Background(), web, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2021-44228" {
		t.Fatalf("hits = %+v", hits)
	}
	worker := ParseInventory(map[string]any{
		"packages": []any{"cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"},
	})
	hits, err = src.Match(context.Background(), worker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("patched demo package matched %+v", hits)
	}
}
