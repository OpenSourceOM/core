package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSlackWebhookFromRequest(t *testing.T) {
	t.Run("accepts webhook in JSON body", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/export/slack",
			strings.NewReader(`{"webhook":"https://example.com/hook"}`),
		)

		webhook, err := slackWebhookFromRequest(req)
		if err != nil {
			t.Fatalf("slackWebhookFromRequest() error = %v", err)
		}

		if webhook != "https://example.com/hook" {
			t.Fatalf("webhook = %q, want %q", webhook, "https://example.com/hook")
		}
	})

	t.Run("rejects webhook query parameter", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/export/slack?webhook=https://example.com/hook",
			nil,
		)

		_, err := slackWebhookFromRequest(req)
		if err == nil {
			t.Fatal("slackWebhookFromRequest() expected error for webhook query parameter")
		}
		if err.Error() != "webhook query parameter is not allowed" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
