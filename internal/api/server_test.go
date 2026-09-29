package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeHealthChecker struct {
	err error
}

func (f fakeHealthChecker) Ping(context.Context) error {
	return f.err
}

func TestHandleHealth(t *testing.T) {
	tests := []struct {
		name       string
		pingErr    error
		wantStatus int
		wantBody   map[string]string
	}{
		{
			name:       "database healthy",
			wantStatus: http.StatusOK,
			wantBody: map[string]string{
				"status":  "ok",
				"service": "opensourceom-api",
			},
		},
		{
			name:       "database unavailable",
			pingErr:    errors.New("postgres is unavailable"),
			wantStatus: http.StatusServiceUnavailable,
			wantBody: map[string]string{
				"status":  "unavailable",
				"service": "opensourceom-api",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{health: fakeHealthChecker{err: tt.pingErr}}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)

			server.handleHealth(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}

			var body map[string]string
			if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			for key, want := range tt.wantBody {
				if got := body[key]; got != want {
					t.Errorf("body[%q] = %q, want %q", key, got, want)
				}
			}
			if _, ok := body["error"]; ok {
				t.Error("health response must not expose the database error")
			}
		})
	}
}

func TestParsePageLimit(t *testing.T) {
	const max = 500
	tests := []struct {
		name    string
		raw     string
		want    int
		wantErr bool
	}{
		{name: "default", want: max},
		{name: "within max", raw: "10", want: 10},
		{name: "at max", raw: "500", want: max},
		{name: "above max", raw: "501", wantErr: true},
		{name: "zero", raw: "0", wantErr: true},
		{name: "negative", raw: "-1", wantErr: true},
		{name: "not a number", raw: "all", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePageLimit(tt.raw, max, max)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePageLimit: %v", err)
			}
			if got != tt.want {
				t.Fatalf("limit = %d, want %d", got, tt.want)
			}
		})
	}
}

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
