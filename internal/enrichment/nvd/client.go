// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenSourceOM/core/internal/enrichment/severity"
)

const (
	defaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	pageSize       = 200
	maxResults     = 200
)

type Client struct {
	apiKey  string
	http    *http.Client
	baseURL string

	mu    sync.Mutex
	byID  map[string]CVE
	byCPE map[string][]CVE
}

// CPEMatch is one vulnerable CPE criterion from an NVD configuration.
type CPEMatch struct {
	Part                  string
	Vendor                string
	Product               string
	Version               string
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
}

type CVE struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	CVSSScore   float64    `json:"cvss_score"`
	Severity    string     `json:"severity"`
	Normalized  int        `json:"normalized_score"`
	Matches     []CPEMatch `json:"-"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http: &http.Client{
			Timeout: 20 * time.Second,
		},
		baseURL: defaultBaseURL,
		byID:    map[string]CVE{},
		byCPE:   map[string][]CVE{},
	}
}

func (c *Client) Lookup(ctx context.Context, cveID string) (CVE, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	c.mu.Lock()
	if hit, ok := c.byID[cveID]; ok {
		c.mu.Unlock()
		return hit, nil
	}
	c.mu.Unlock()

	q := url.Values{}
	q.Set("cveId", cveID)
	payload, err := c.get(ctx, q)
	if err != nil {
		return CVE{}, err
	}
	if len(payload.Vulnerabilities) == 0 {
		return CVE{}, fmt.Errorf("cve %s not found in NVD", cveID)
	}
	out := cveFromNVD(payload.Vulnerabilities[0].CVE)
	c.mu.Lock()
	c.byID[out.ID] = out
	c.mu.Unlock()
	return out, nil
}

// SearchCPE returns CVEs whose configurations virtually match cpe.
// The caller still checks version ranges. More than maxResults is an error
// so a broad CPE cannot silently drop rows.
func (c *Client) SearchCPE(ctx context.Context, cpe string) ([]CVE, error) {
	c.mu.Lock()
	if hit, ok := c.byCPE[cpe]; ok {
		c.mu.Unlock()
		return hit, nil
	}
	c.mu.Unlock()

	var all []CVE
	start := 0
	for {
		q := url.Values{}
		q.Set("virtualMatchString", cpe)
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(start))
		payload, err := c.get(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("nvd search %s: %w", cpe, err)
		}
		if payload.TotalResults > maxResults {
			return nil, fmt.Errorf("nvd returned %d cves for %s", payload.TotalResults, cpe)
		}
		for _, item := range payload.Vulnerabilities {
			all = append(all, cveFromNVD(item.CVE))
		}
		start += len(payload.Vulnerabilities)
		if start >= payload.TotalResults || len(payload.Vulnerabilities) == 0 {
			break
		}
	}
	c.mu.Lock()
	c.byCPE[cpe] = all
	for _, item := range all {
		if _, ok := c.byID[item.ID]; !ok {
			c.byID[item.ID] = item
		}
	}
	c.mu.Unlock()
	return all, nil
}

func (c *Client) get(ctx context.Context, q url.Values) (nvdResponse, error) {
	reqURL := c.baseURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nvdResponse{}, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nvdResponse{}, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nvdResponse{}, fmt.Errorf("read nvd response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nvdResponse{}, fmt.Errorf("nvd returned status %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nvdResponse{}, fmt.Errorf("decode nvd response: %w", err)
	}
	return payload, nil
}

func cveFromNVD(item nvdCVE) CVE {
	out := CVE{ID: item.ID}
	for _, desc := range item.Descriptions {
		if desc.Lang == "en" {
			out.Description = desc.Value
			break
		}
	}
	if out.Description != "" {
		out.Title = truncate(out.Description, 120)
	} else {
		out.Title = item.ID
	}

	out.CVSSScore, out.Severity = extractCVSS(item.Metrics)
	if out.Severity == "" {
		out.Severity = severity.LevelInfo
	}
	if out.CVSSScore > 0 {
		out.Severity, out.Normalized = severity.FromCVSS(out.CVSSScore)
	} else {
		out.Severity = severity.FromLabel(out.Severity)
		out.Normalized = severity.NormalizedScore(out.Severity)
	}
	out.Matches = cpeMatches(item.Configurations)
	return out
}

func cpeMatches(configs []nvdConfig) []CPEMatch {
	var out []CPEMatch
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				parsed, ok := parseCriteria(match.Criteria)
				if !ok {
					continue
				}
				parsed.VersionStartIncluding = match.VersionStartIncluding
				parsed.VersionStartExcluding = match.VersionStartExcluding
				parsed.VersionEndIncluding = match.VersionEndIncluding
				parsed.VersionEndExcluding = match.VersionEndExcluding
				out = append(out, parsed)
			}
		}
	}
	return out
}

func parseCriteria(criteria string) (CPEMatch, bool) {
	fields := splitCPE(criteria)
	if len(fields) < 6 || fields[0] != "cpe" || fields[1] != "2.3" {
		return CPEMatch{}, false
	}
	return CPEMatch{
		Part:    fields[2],
		Vendor:  fields[3],
		Product: fields[4],
		Version: fields[5],
	}, true
}

func splitCPE(s string) []string {
	var fields []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			fields = append(fields, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	fields = append(fields, b.String())
	return fields
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        nvdMetrics  `json:"metrics"`
	Configurations []nvdConfig `json:"configurations"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Negate   bool          `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func extractCVSS(metrics nvdMetrics) (score float64, label string) {
	buckets := [][]nvdCVSSMetric{
		metrics.CVSSMetricV31,
		metrics.CVSSMetricV30,
		metrics.CVSSMetricV2,
	}
	for _, bucket := range buckets {
		if len(bucket) > 0 {
			return bucket[0].CVSSData.BaseScore, bucket[0].CVSSData.BaseSeverity
		}
	}
	return 0, ""
}

func truncate(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
