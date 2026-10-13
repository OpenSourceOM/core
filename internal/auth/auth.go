// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

// Package auth stores console admins and talks to Google and GitHub for login.
// Every account is an admin. Roles, SAML, and custom identity providers are out
// of scope.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"

	inviteTTL  = 72 * time.Hour
	sessionTTL = 7 * 24 * time.Hour
)

var (
	ErrNotFound        = errors.New("admin not found")
	ErrLastAdmin       = errors.New("last admin")
	ErrAdminsExist     = errors.New("admins already exist")
	ErrInviteInvalid   = errors.New("invite invalid")
	ErrInviteUsed      = errors.New("invite used")
	ErrInviteExpired   = errors.New("invite expired")
	ErrEmailUnverified = errors.New("email unverified")
)

// Admin is a console operator. Provider and Subject are the identity.
// Login and Name are labels from the identity provider.
type Admin struct {
	ID        string
	Provider  string
	Subject   string
	Login     string
	Name      string
	CreatedAt time.Time
}

// Identity is the account an identity provider just confirmed.
type Identity struct {
	Provider string
	Subject  string
	Login    string
	Name     string
}

// Provider starts a login and exchanges the callback code for an identity.
type Provider interface {
	Name() string
	AuthCodeURL(state, redirectURL string) string
	Exchange(ctx context.Context, code, redirectURL string) (Identity, error)
}

// Directory is the console admin store the API uses.
type Directory interface {
	Count(ctx context.Context) (int, error)
	List(ctx context.Context) ([]Admin, error)
	Delete(ctx context.Context, id string) error
	Find(ctx context.Context, provider, subject string) (Admin, bool, error)
	CreateSession(ctx context.Context, adminID string) (sessionID string, expires time.Time, err error)
	DeleteSession(ctx context.Context, sessionID string) error
	AdminForSession(ctx context.Context, sessionID string) (Admin, error)
	CreateInvite(ctx context.Context, createdBy string) (token string, expires time.Time, err error)
	PeekInvite(ctx context.Context, token string) error
	AcceptInvite(ctx context.Context, token string, identity Identity) (Admin, error)
}

// NewToken returns a URL-safe secret.
func NewToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// HashToken is the value stored for an invite or a session.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (id Identity) normalized() (Identity, error) {
	id.Provider = strings.TrimSpace(id.Provider)
	id.Subject = strings.TrimSpace(id.Subject)
	id.Login = clip(id.Login, 200)
	id.Name = clip(id.Name, 200)
	if id.Provider != ProviderGoogle && id.Provider != ProviderGitHub {
		return Identity{}, errors.New("unknown provider")
	}
	if id.Subject == "" {
		return Identity{}, errors.New("missing subject")
	}
	if id.Login == "" {
		id.Login = id.Subject
	}
	return id, nil
}

func clip(value string, max int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func inviteToken(token string) (string, error) {
	if token == "" || len(token) > 128 {
		return "", ErrInviteInvalid
	}
	return HashToken(token), nil
}
