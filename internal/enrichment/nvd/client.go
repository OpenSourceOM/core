// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/enrichment/severity"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type Client struct {
	apiKey string
	http   *http.Client
}

type CVE struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	CVSSScore   float64 `json:"cvss_score"`
	Severity    string  `json:"severity"`
	Normalized  int     `json:"normalized_score"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) Lookup(ctx context.Context, cveID string) (CVE, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	reqURL := baseURL + "?cveId=" + url.QueryEscape(cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return CVE{}, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return CVE{}, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CVE{}, fmt.Errorf("nvd returned status %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return CVE{}, fmt.Errorf("decode nvd response: %w", err)
	}
	if len(payload.Vulnerabilities) == 0 {
		return CVE{}, fmt.Errorf("cve %s not found in NVD", cveID)
	}

	item := payload.Vulnerabilities[0].CVE
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

	return out, nil
}

type nvdResponse struct {
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
	Metrics nvdMetrics `json:"metrics"`
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
