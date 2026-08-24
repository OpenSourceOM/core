// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
)

type FindingRecord struct {
	Timestamp    time.Time      `json:"timestamp"`
	Finding      graph.Node     `json:"finding"`
	AffectedID   string         `json:"affected_resource_id,omitempty"`
	AffectedName string         `json:"affected_resource_name,omitempty"`
	AffectedType string         `json:"affected_resource_type,omitempty"`
}

func LoadFindingRecords(ctx context.Context, store *graph.Store) ([]FindingRecord, error) {
	views, err := store.ListFindings(ctx, 500)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	records := make([]FindingRecord, 0, len(views))
	for _, view := range views {
		records = append(records, FindingRecord{
			Timestamp:    now,
			Finding:      view.Finding,
			AffectedID:   view.AffectedResourceID,
			AffectedName: view.AffectedResourceName,
			AffectedType: view.AffectedResourceType,
		})
	}
	return records, nil
}

func WriteSIEM(w io.Writer, records []FindingRecord) error {
	enc := json.NewEncoder(w)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func PostSlack(ctx context.Context, webhookURL string, records []FindingRecord) error {
	if webhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL is required")
	}
	var lines []string
	lines = append(lines, "*OpenSourceOM findings export*")
	if len(records) == 0 {
		lines = append(lines, "No findings to export.")
	}
	for i, record := range records {
		if i >= 20 {
			lines = append(lines, fmt.Sprintf("…and %d more", len(records)-20))
			break
		}
		severity, _ := record.Finding.Properties["severity"].(string)
		title, _ := record.Finding.Properties["title"].(string)
		if title == "" {
			title = record.Finding.Name
		}
		lines = append(lines, fmt.Sprintf("• [%s] %s — %s", strings.ToUpper(severity), title, record.AffectedName))
	}
	payload, err := json.Marshal(map[string]string{"text": strings.Join(lines, "\n")})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

type JiraConfig struct {
	BaseURL  string
	Email    string
	APIToken string
	Project  string
}

func CreateJiraIssues(ctx context.Context, cfg JiraConfig, records []FindingRecord) (int, error) {
	if cfg.BaseURL == "" || cfg.Email == "" || cfg.APIToken == "" || cfg.Project == "" {
		return 0, fmt.Errorf("JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT are required")
	}
	created := 0
	for _, record := range records {
		title, _ := record.Finding.Properties["title"].(string)
		if title == "" {
			title = record.Finding.Name
		}
		desc, _ := record.Finding.Properties["description"].(string)
		severity, _ := record.Finding.Properties["severity"].(string)
		payload := map[string]any{
			"fields": map[string]any{
				"project": map[string]string{"key": cfg.Project},
				"summary": fmt.Sprintf("[%s] %s", strings.ToUpper(severity), title),
				"issuetype": map[string]string{"name": "Task"},
				"description": map[string]any{
					"type":    "doc",
					"version": 1,
					"content": []map[string]any{
						{
							"type": "paragraph",
							"content": []map[string]string{
								{"type": "text", "text": fmt.Sprintf("%s\nAffected: %s (%s)", desc, record.AffectedName, record.AffectedType)},
							},
						},
					},
				},
			},
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return created, err
		}
		url := strings.TrimRight(cfg.BaseURL, "/") + "/rest/api/3/issue"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return created, err
		}
		req.SetBasicAuth(cfg.Email, cfg.APIToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return created, err
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return created, fmt.Errorf("jira create issue returned %d", resp.StatusCode)
		}
		created++
	}
	return created, nil
}
