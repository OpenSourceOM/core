// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestProvidersFromConfigSkipsPartialPairs(t *testing.T) {
	providers := ProvidersFromConfig("gid", "", "", "ghs")
	if len(providers) != 0 {
		t.Fatalf("providers = %d", len(providers))
	}
	providers = ProvidersFromConfig("gid", "gs", "hid", "hs")
	if providers[ProviderGoogle] == nil || providers[ProviderGitHub] == nil {
		t.Fatalf("providers = %#v", providers)
	}
}

func TestGoogleExchangeUsesSubject(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = io.WriteString(w, `{"sub":"gsub","email":"a@example.com","email_verified":true,"name":"Ada"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newGoogle("id", "secret")
	provider.config.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	provider.userInfoURL = server.URL + "/userinfo"

	identity, err := provider.Exchange(context.Background(), "code", "http://localhost:8080/auth/google/callback")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != ProviderGoogle || identity.Subject != "gsub" || identity.Login != "a@example.com" || identity.Name != "Ada" {
		t.Fatalf("identity = %+v", identity)
	}
	if !strings.Contains(userAgent, "OpenSourceOM") {
		t.Fatalf("user agent = %q", userAgent)
	}
}

func TestGoogleExchangeRejectsUnverifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"sub":"gsub","email":"a@example.com","email_verified":false}`)
	}))
	defer server.Close()

	provider := newGoogle("id", "secret")
	provider.config.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	provider.userInfoURL = server.URL + "/userinfo"
	_, err := provider.Exchange(context.Background(), "code", "http://localhost/cb")
	if err != ErrEmailUnverified {
		t.Fatalf("err = %v", err)
	}
}

func TestGitHubExchangeUsesNumericID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		_, _ = io.WriteString(w, `{"id":42,"login":"octocat","name":"Mona"}`)
	}))
	defer server.Close()

	provider := newGitHub("id", "secret")
	provider.config.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	provider.userInfoURL = server.URL + "/user"
	identity, err := provider.Exchange(context.Background(), "code", "http://localhost/cb")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "42" || identity.Login != "octocat" || identity.Provider != ProviderGitHub {
		t.Fatalf("identity = %+v", identity)
	}
}
