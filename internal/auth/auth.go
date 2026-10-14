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
	ProviderGoogle   = "google"
	ProviderGitHub   = "github"
	ProviderPassword = "password"

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
	ErrEmailMismatch   = errors.New("email mismatch")
	ErrInvalidEmail    = errors.New("invalid email")
	ErrPasswordShort   = errors.New("password too short")
	ErrEmailTaken      = errors.New("email taken")
	ErrBadCredentials  = errors.New("invalid email or password")
	ErrSetupEmail      = errors.New("setup email mismatch")
	ErrTOTPInvalid     = errors.New("invalid authentication code")
	ErrTOTPEnabled     = errors.New("two-factor authentication is already on")
)

// Admin is a console operator. Password accounts use provider "password".
// Google and GitHub are optional sign-in methods matched by verified email.
type Admin struct {
	ID                 string
	Provider           string
	Subject            string
	Login              string
	Name               string
	Email              string
	MustChangePassword bool
	TOTPEnabled        bool
	CreatedAt          time.Time
}

// Identity is the account an identity provider just confirmed.
// Emails are the verified addresses on that account.
type Identity struct {
	Provider string
	Subject  string
	Login    string
	Name     string
	Emails   []string
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
	FindByEmail(ctx context.Context, email string) (Admin, bool, error)
	SetupAdmin(ctx context.Context, email, password, pinnedEmail string) (Admin, error)
	CreateWithPassword(ctx context.Context, email, password string, mustChange bool) (Admin, error)
	ProvisionAdmin(ctx context.Context, email string) (Admin, string, error)
	CheckPassword(ctx context.Context, email, password string) (Admin, error)
	ChangePassword(ctx context.Context, adminID, current, next string) error
	SetPassword(ctx context.Context, email, password string) error
	BeginTOTP(ctx context.Context, adminID string) (secret string, err error)
	ConfirmTOTP(ctx context.Context, adminID, code string) (recoveryCodes []string, err error)
	DisableTOTP(ctx context.Context, adminID, password, code string) error
	VerifySecondFactor(ctx context.Context, adminID, code string) error
	CreateLoginChallenge(ctx context.Context, adminID string) (token string, err error)
	ConsumeLoginChallenge(ctx context.Context, token string) (Admin, error)
	AdminForToken(ctx context.Context, token string) (Admin, error)
	TakeTokenPreview(ctx context.Context, adminID string) (string, error)
	RotateToken(ctx context.Context, adminID string) (string, error)
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
	id.Emails = normalizeEmailList(id.Emails)
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

func (id Identity) hasEmail(want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, email := range id.Emails {
		if email == want {
			return true
		}
	}
	return false
}

// NormalizeEmail returns a lowercased address suitable for an invite.
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) == 0 || len(email) > 200 || strings.ContainsAny(email, " \t\r\n<>") {
		return "", ErrInvalidEmail
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || !strings.Contains(domain, ".") || strings.Contains(domain, "@") {
		return "", ErrInvalidEmail
	}
	return email, nil
}

func normalizeEmailList(emails []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, email := range emails {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" || seen[email] {
			continue
		}
		if _, err := NormalizeEmail(email); err != nil {
			continue
		}
		seen[email] = true
		out = append(out, email)
	}
	return out
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
