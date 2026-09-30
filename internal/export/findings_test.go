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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestWriteSIEM(t *testing.T) {
	when := time.Date(2026, 9, 30, 15, 4, 5, 0, time.UTC)
	records := []FindingRecord{
		{
			Timestamp: when,
			Finding: graph.Node{
				ID:   "finding:cve:web",
				Type: graph.NodeFinding,
				Name: "CVE-2021-44228",
				Properties: map[string]any{
					"severity": "critical",
					"title":    "Log4Shell",
				},
			},
			AffectedID:   "workload:web",
			AffectedName: "web-1",
			AffectedType: graph.NodeWorkload,
			Path:         []string{"internet:global", "workload:web", "datastore:prod"},
		},
		{
			Timestamp: when,
			Finding: graph.Node{
				ID:   "finding:public:bucket",
				Type: graph.NodeFinding,
				Name: "Public bucket",
			},
			AffectedID:   "datastore:logs",
			AffectedName: "logs",
			AffectedType: graph.NodeDatastore,
		},
	}

	var buf bytes.Buffer
	if err := WriteSIEM(&buf, records); err != nil {
		t.Fatalf("WriteSIEM: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != len(records) {
		t.Fatalf("lines = %d, want %d", len(lines), len(records))
	}
	for i, line := range lines {
		var got FindingRecord
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if !got.Timestamp.Equal(records[i].Timestamp) {
			t.Fatalf("line %d timestamp = %s", i, got.Timestamp)
		}
		if got.Finding.ID != records[i].Finding.ID || got.AffectedName != records[i].AffectedName {
			t.Fatalf("line %d = finding %s affected %s", i, got.Finding.ID, got.AffectedName)
		}
		if strings.Join(got.Path, ",") != strings.Join(records[i].Path, ",") {
			t.Fatalf("line %d path = %v", i, got.Path)
		}
	}

	buf.Reset()
	if err := WriteSIEM(&buf, nil); err != nil {
		t.Fatalf("WriteSIEM empty: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("empty export wrote %q", buf.String())
	}
}

func TestPostSlackTruncatesAfterTwenty(t *testing.T) {
	if err := PostSlack(context.Background(), "", nil); err == nil || !strings.Contains(err.Error(), "SLACK_WEBHOOK_URL") {
		t.Fatalf("empty webhook error = %v", err)
	}

	var text string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode: %v", err)
		}
		text = payload["text"]
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	records := make([]FindingRecord, 21)
	for i := range records {
		records[i] = FindingRecord{
			Finding: graph.Node{
				Name: fmt.Sprintf("name-%02d", i),
				Properties: map[string]any{
					"severity": "high",
					"title":    fmt.Sprintf("title-%02d", i),
				},
			},
			AffectedName: fmt.Sprintf("res-%02d", i),
		}
	}
	records[0].Finding.Properties["title"] = ""

	if err := PostSlack(context.Background(), server.URL, records); err != nil {
		t.Fatalf("PostSlack: %v", err)
	}
	lines := strings.Split(text, "\n")
	if len(lines) != 22 {
		t.Fatalf("lines = %d, want header, 20 findings, and the remainder", len(lines))
	}
	if lines[0] != "*OpenSourceOM findings export*" {
		t.Fatalf("header = %q", lines[0])
	}
	if lines[1] != "• [HIGH] name-00 — res-00" {
		t.Fatalf("first finding = %q", lines[1])
	}
	if lines[20] != "• [HIGH] title-19 — res-19" {
		t.Fatalf("twentieth finding = %q", lines[20])
	}
	if lines[21] != "…and 1 more" {
		t.Fatalf("remainder = %q", lines[21])
	}
	if strings.Contains(text, "title-20") {
		t.Fatalf("message includes the finding past the cutoff:\n%s", text)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(fail.Close)
	err := PostSlack(context.Background(), fail.URL, records[:1])
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("webhook error = %v", err)
	}
}

func TestCreateJiraIssues(t *testing.T) {
	_, err := CreateJiraIssues(context.Background(), JiraConfig{}, []FindingRecord{{}})
	if err == nil || !strings.Contains(err.Error(), "JIRA_URL") {
		t.Fatalf("missing config error = %v", err)
	}

	var (
		user, pass string
		bodies     []map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue" {
			t.Errorf("path = %s", r.URL.Path)
		}
		user, pass, _ = r.BasicAuth()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode: %v", err)
		}
		bodies = append(bodies, payload)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	record := FindingRecord{
		Finding: graph.Node{
			Name: "fallback",
			Properties: map[string]any{
				"severity":    "critical",
				"title":       "Log4Shell",
				"description": "Remote code execution",
			},
		},
		AffectedName: "web-1",
		AffectedType: graph.NodeWorkload,
	}
	cfg := JiraConfig{
		BaseURL:  server.URL + "/",
		Email:    "bot@example.com",
		APIToken: "tok",
		Project:  "SEC",
	}
	created, err := CreateJiraIssues(context.Background(), cfg, []FindingRecord{record})
	if err != nil {
		t.Fatalf("CreateJiraIssues: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if user != cfg.Email || pass != cfg.APIToken {
		t.Fatalf("basic auth = %s:%s", user, pass)
	}
	if len(bodies) != 1 {
		t.Fatalf("requests = %d", len(bodies))
	}
	fields, _ := bodies[0]["fields"].(map[string]any)
	project, _ := fields["project"].(map[string]any)
	if project["key"] != "SEC" {
		t.Fatalf("project = %v", fields["project"])
	}
	if fields["summary"] != "[CRITICAL] Log4Shell" {
		t.Fatalf("summary = %v", fields["summary"])
	}
	description := jiraDescriptionText(t, fields["description"])
	if description != "Remote code execution\nAffected: web-1 (Workload)" {
		t.Fatalf("description = %q", description)
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(denied.Close)
	cfg.BaseURL = denied.URL
	created, err = CreateJiraIssues(context.Background(), cfg, []FindingRecord{record})
	if err == nil || !strings.Contains(err.Error(), "403") || created != 0 {
		t.Fatalf("denied create = (%d, %v)", created, err)
	}
}

func jiraDescriptionText(t *testing.T, description any) string {
	t.Helper()
	doc, _ := description.(map[string]any)
	content, _ := doc["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("description content = %v", description)
	}
	paragraph, _ := content[0].(map[string]any)
	parts, _ := paragraph["content"].([]any)
	if len(parts) != 1 {
		t.Fatalf("paragraph = %v", paragraph)
	}
	part, _ := parts[0].(map[string]any)
	text, _ := part["text"].(string)
	return text
}
