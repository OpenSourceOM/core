// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/OpenSourceOM/core/internal/auth"
)

const (
	sessionCookie = "om_session"
	oauthCookie   = "om_oauth"
	loginCookie   = "om_login"
	oauthTTL      = 10 * time.Minute
)

// ConsoleAuth wires Google and GitHub login for the embedded console.
type ConsoleAuth struct {
	Directory    auth.Directory
	PublicURL    string
	Providers    map[string]auth.Provider
	SetupEmail   string
	SendPassword func(ctx context.Context, to, password string) error
	SendReset    func(ctx context.Context, to, resetURL string) error
}

func (s *Server) WithConsoleAuth(cfg ConsoleAuth) *Server {
	s.admins = cfg.Directory
	s.publicURL = strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	s.providers = cfg.Providers
	s.setupEmail = strings.TrimSpace(cfg.SetupEmail)
	s.sendPassword = cfg.SendPassword
	s.sendReset = cfg.SendReset
	s.secureCookies = strings.HasPrefix(s.publicURL, "https://")
	if s.loginLimit == nil {
		s.loginLimit = newLoginLimiter()
	}
	return s
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"login_enabled": false,
			"needs_setup":   false,
			"providers":     []string{},
		})
		return
	}
	count, err := s.admins.Count(r.Context())
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	body := map[string]any{
		"authenticated":  false,
		"login_enabled":  true,
		"needs_setup":    count == 0,
		"password_reset": s.sendReset != nil,
		"providers":      s.providerNames(),
	}
	if count == 0 && s.setupEmail != "" {
		body["setup_email"] = s.setupEmail
	}
	if admin, ok := s.currentAdmin(r); ok {
		body["authenticated"] = true
		view := adminView(admin)
		if !admin.MustChangePassword {
			hasToken, err := s.admins.HasToken(r.Context(), admin.ID)
			if err != nil {
				writeAdminStoreError(w, err)
				return
			}
			view["has_api_token"] = hasToken
		}
		body["admin"] = view
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if cookie, err := r.Cookie(sessionCookie); err == nil && s.admins != nil {
		_ = s.admins.DeleteSession(r.Context(), cookie.Value)
	}
	s.clearCookie(w, sessionCookie, "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	admins, err := s.admins.List(r.Context())
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(admins))
	for _, admin := range admins {
		views = append(views, adminView(admin))
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": views})
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email"})
		return
	}
	email, err := auth.NormalizeEmail(req.Email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email"})
		return
	}
	_, password, err := s.admins.ProvisionAdmin(r.Context(), email)
	if errors.Is(err, auth.ErrEmailTaken) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "An admin with that email already exists."})
		return
	}
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	emailed := false
	if s.sendPassword != nil {
		if err := s.sendPassword(r.Context(), email, password); err != nil {
			log.Printf("admin password email: %v", err)
		} else {
			emailed = true
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"email":    email,
		"password": password,
		"emailed":  emailed,
	})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	token, err := s.admins.CreateToken(r.Context(), admin.ID)
	if errors.Is(err, auth.ErrTokenExists) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "An API token already exists. Rotate it to replace the current one."})
		return
	}
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	token, err := s.admins.RotateToken(r.Context(), admin.ID)
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	err := s.admins.Delete(r.Context(), r.PathValue("id"))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin not found"})
	case errors.Is(err, auth.ErrLastAdmin):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the last admin cannot be removed"})
	default:
		writeAdminStoreError(w, err)
	}
}

func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	provider, ok := s.providers[name]
	if !ok || s.admins == nil {
		s.redirectAuthError(w, r, "provider_unconfigured")
		return
	}
	if !validPublicURL(s.publicURL) {
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}
	state, err := auth.NewToken()
	if err != nil {
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}
	if err := s.setOAuthCookie(w, oauthPayload{State: state, Provider: name}); err != nil {
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}
	http.Redirect(w, r, provider.AuthCodeURL(state, s.redirectURI(name)), http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	payload, err := s.readOAuthCookie(r)
	s.clearCookie(w, oauthCookie, "/auth")
	if r.URL.Query().Get("error") != "" {
		s.redirectAuthError(w, r, "oauth_denied")
		return
	}
	queryState := r.URL.Query().Get("state")
	if err != nil || payload.Provider != name || !sameSecret(payload.State, queryState) {
		s.redirectAuthError(w, r, "oauth_state")
		return
	}
	provider, ok := s.providers[name]
	code := r.URL.Query().Get("code")
	if !ok || s.admins == nil || code == "" {
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	identity, err := provider.Exchange(ctx, code, s.redirectURI(name))
	if errors.Is(err, auth.ErrEmailUnverified) {
		s.redirectAuthError(w, r, "email_unverified")
		return
	}
	if err != nil {
		log.Printf("oauth %s: %v", name, err)
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}

	if len(identity.Emails) == 0 {
		s.redirectAuthError(w, r, "email_unverified")
		return
	}
	var admin auth.Admin
	var found bool
	for _, email := range identity.Emails {
		admin, found, err = s.admins.FindByEmail(r.Context(), email)
		if err != nil {
			log.Printf("oauth %s lookup: %v", name, err)
			s.redirectAuthError(w, r, "oauth_failed")
			return
		}
		if found {
			break
		}
	}
	if !found {
		s.redirectAuthError(w, r, "not_admin")
		return
	}
	if admin.TOTPEnabled {
		token, err := s.admins.CreateLoginChallenge(r.Context(), admin.ID)
		if err != nil {
			s.redirectAuthError(w, r, "oauth_failed")
			return
		}
		s.setLoginCookie(w, token)
		http.Redirect(w, r, "/login?totp=1", http.StatusFound)
		return
	}

	sessionID, expires, err := s.admins.CreateSession(r.Context(), admin.ID)
	if err != nil {
		log.Printf("oauth %s session: %v", name, err)
		s.redirectAuthError(w, r, "oauth_failed")
		return
	}
	s.setSessionCookie(w, sessionID, expires)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleConsolePage(w http.ResponseWriter, r *http.Request) {
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "console unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

type oauthPayload struct {
	State    string `json:"state"`
	Invite   string `json:"invite,omitempty"`
	Provider string `json:"provider"`
}

func (s *Server) currentAdmin(r *http.Request) (auth.Admin, bool) {
	if s.admins == nil {
		return auth.Admin{}, false
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return auth.Admin{}, false
	}
	admin, err := s.admins.AdminForSession(r.Context(), cookie.Value)
	if err != nil {
		return auth.Admin{}, false
	}
	return admin, true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (auth.Admin, bool) {
	admin, ok := s.currentAdmin(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return auth.Admin{}, false
	}
	return admin, true
}

func (s *Server) providerNames() []string {
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Server) redirectURI(provider string) string {
	return s.publicURL + "/auth/" + provider + "/callback"
}

func (s *Server) redirectAuthError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
	})
}

func (s *Server) setOAuthCookie(w http.ResponseWriter, payload oauthPayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/auth",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
		MaxAge:   int(oauthTTL.Seconds()),
	})
	return nil
}

func (s *Server) readOAuthCookie(r *http.Request) (oauthPayload, error) {
	cookie, err := r.Cookie(oauthCookie)
	if err != nil {
		return oauthPayload{}, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return oauthPayload{}, err
	}
	var payload oauthPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return oauthPayload{}, err
	}
	if payload.State == "" || payload.Provider == "" {
		return oauthPayload{}, errors.New("incomplete oauth state")
	}
	return payload, nil
}

func (s *Server) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
		MaxAge:   -1,
	})
}

func adminView(admin auth.Admin) map[string]any {
	return map[string]any{
		"id":                   admin.ID,
		"provider":             admin.Provider,
		"login":                admin.Login,
		"name":                 admin.Name,
		"email":                admin.Email,
		"must_change_password": admin.MustChangePassword,
		"totp_enabled":         admin.TOTPEnabled,
	}
}

func validPublicURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func sameSecret(a, b string) bool {
	if a == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeAdminStoreError(w http.ResponseWriter, err error) {
	if undefinedTable(err) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "The database has not been initialized. Run om migrate, then refresh this page.",
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "admin store failed"})
}

func undefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

func publicV1(r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/v1/version":
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/session":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/logout":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/setup":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/totp":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/forgot":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/reset":
		return true
	default:
		return false
	}
}
