// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupParsesVulnerableRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Errorf("cveId = %q", r.URL.Query().Get("cveId"))
		}
		if r.Header.Get("apiKey") != "test-key" {
			t.Errorf("apiKey = %q", r.Header.Get("apiKey"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(log4jBody))
	}))
	defer srv.Close()

	client := NewClient("test-key")
	client.baseURL = srv.URL
	cve, err := client.Lookup(context.Background(), "cve-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if cve.ID != "CVE-2021-44228" || cve.CVSSScore != 10 || cve.Severity != "critical" || cve.Normalized != 95 {
		t.Fatalf("cve = %+v", cve)
	}
	if len(cve.Matches) != 1 {
		t.Fatalf("matches = %+v", cve.Matches)
	}
	m := cve.Matches[0]
	if m.Vendor != "apache" || m.Product != "log4j" || m.VersionEndIncluding != "2.14.1" || m.VersionStartIncluding != "2.0" {
		t.Fatalf("match = %+v", m)
	}

	again, err := client.Lookup(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != cve.ID {
		t.Fatalf("cached id = %s", again.ID)
	}
}

func TestSearchCPEUsesVirtualMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("virtualMatchString"); !strings.Contains(got, "apache:log4j:2.14.1") {
			t.Errorf("virtualMatchString = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	client := NewClient("")
	client.baseURL = srv.URL
	got, err := client.SearchCPE(context.Background(), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("cves = %d", len(got))
	}
}

func TestSearchCPERejectsHugeResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":201,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	client := NewClient("")
	client.baseURL = srv.URL
	_, err := client.SearchCPE(context.Background(), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	if err == nil || !strings.Contains(err.Error(), "201") {
		t.Fatalf("err = %v", err)
	}
}

const log4jBody = `{
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
          {"lang": "en", "value": "Apache Log4j2 2.0 through 2.14.1 JNDI features do not protect against attacker controlled LDAP."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
          ]
        },
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": false,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
                  },
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.0",
                    "versionEndIncluding": "2.14.1"
                  }
                ]
              },
              {
                "operator": "OR",
                "negate": true,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:apache:log4j:9.9.9:*:*:*:*:*:*:*"
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}`
