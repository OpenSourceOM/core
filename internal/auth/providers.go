// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const userAgent = "OpenSourceOM"

// ProvidersFromConfig returns the identity providers that have both a client
// id and a client secret. A half-set pair is ignored.
func ProvidersFromConfig(googleID, googleSecret, githubID, githubSecret string) map[string]Provider {
	providers := make(map[string]Provider)
	if googleID != "" && googleSecret != "" {
		providers[ProviderGoogle] = newGoogle(googleID, googleSecret)
	}
	if githubID != "" && githubSecret != "" {
		providers[ProviderGitHub] = newGitHub(githubID, githubSecret)
	}
	return providers
}

type oauthProvider struct {
	name           string
	config         oauth2.Config
	userInfoURL    string
	userInfoAccept string
	emailsURL      string
	parse          func([]byte) (Identity, error)
}

func (p *oauthProvider) Name() string { return p.name }

func (p *oauthProvider) AuthCodeURL(state, redirectURL string) string {
	cfg := p.config
	cfg.RedirectURL = redirectURL
	return cfg.AuthCodeURL(state)
}

func (p *oauthProvider) Exchange(ctx context.Context, code, redirectURL string) (Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: userAgentRoundTripper{base: http.DefaultTransport, agent: userAgent},
	})
	cfg := p.config
	cfg.RedirectURL = redirectURL
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return Identity{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	if p.userInfoAccept != "" {
		req.Header.Set("Accept", p.userInfoAccept)
	}
	resp, err := cfg.Client(ctx, tok).Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("%s userinfo status %d", p.name, resp.StatusCode)
	}
	identity, err := p.parse(body)
	if err != nil {
		return Identity{}, err
	}
	if p.emailsURL == "" {
		return identity, nil
	}
	emails, err := p.fetchVerifiedEmails(ctx, cfg.Client(ctx, tok))
	if err != nil {
		return Identity{}, err
	}
	if len(emails) == 0 {
		return Identity{}, ErrEmailUnverified
	}
	identity.Emails = emails
	return identity.normalized()
}

func (p *oauthProvider) fetchVerifiedEmails(ctx context.Context, client *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.emailsURL, nil)
	if err != nil {
		return nil, err
	}
	if p.userInfoAccept != "" {
		req.Header.Set("Accept", p.userInfoAccept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s emails status %d", p.name, resp.StatusCode)
	}
	var rows []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var emails []string
	for _, row := range rows {
		if row.Verified {
			emails = append(emails, row.Email)
		}
	}
	return emails, nil
}

func newGoogle(clientID, clientSecret string) *oauthProvider {
	return &oauthProvider{
		name: ProviderGoogle,
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email", "profile"},
		},
		userInfoURL:    "https://openidconnect.googleapis.com/v1/userinfo",
		userInfoAccept: "application/json",
		parse:          parseGoogle,
	}
}

func newGitHub(clientID, clientSecret string) *oauthProvider {
	return &oauthProvider{
		name: ProviderGitHub,
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     github.Endpoint,
			Scopes:       []string{"read:user", "user:email"},
		},
		userInfoURL:    "https://api.github.com/user",
		emailsURL:      "https://api.github.com/user/emails",
		userInfoAccept: "application/vnd.github+json",
		parse:          parseGitHub,
	}
}

func parseGoogle(body []byte) (Identity, error) {
	var user struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return Identity{}, err
	}
	if strings.TrimSpace(user.Sub) == "" {
		return Identity{}, fmt.Errorf("google userinfo missing sub")
	}
	if !user.EmailVerified {
		return Identity{}, ErrEmailUnverified
	}
	return Identity{
		Provider: ProviderGoogle,
		Subject:  user.Sub,
		Login:    user.Email,
		Name:     user.Name,
		Emails:   []string{user.Email},
	}.normalized()
}

func parseGitHub(body []byte) (Identity, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return Identity{}, err
	}
	if user.ID <= 0 {
		return Identity{}, fmt.Errorf("github userinfo missing id")
	}
	return Identity{
		Provider: ProviderGitHub,
		Subject:  strconv.FormatInt(user.ID, 10),
		Login:    user.Login,
		Name:     user.Name,
	}.normalized()
}

type userAgentRoundTripper struct {
	base  http.RoundTripper
	agent string
}

func (t userAgentRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", t.agent)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
