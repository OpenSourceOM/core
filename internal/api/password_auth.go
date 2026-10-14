// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/auth"
)

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console login is not available"})
		return
	}
	if s.tooManyAttempts(r, "setup") {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many attempts. Try again later."})
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter an email and a password."})
		return
	}
	email := req.Email
	if s.setupEmail != "" {
		email = s.setupEmail
	}
	admin, err := s.admins.SetupAdmin(r.Context(), email, req.Password, s.setupEmail)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrAdminsExist):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "An admin already exists. Sign in."})
		return
	case errors.Is(err, auth.ErrSetupEmail):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "This install already has an admin email."})
		return
	case errors.Is(err, auth.ErrInvalidEmail):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a valid email address."})
		return
	case errors.Is(err, auth.ErrPasswordShort):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Use at least 12 characters."})
		return
	default:
		writeAdminStoreError(w, err)
		return
	}
	s.startSession(w, r, admin)
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console login is not available"})
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter an email and a password."})
		return
	}
	if s.tooManyAttempts(r, req.Email) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many attempts. Try again later."})
		return
	}
	admin, err := s.admins.CheckPassword(r.Context(), req.Email, req.Password)
	if errors.Is(err, auth.ErrBadCredentials) {
		s.noteFailure(r, req.Email)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid email or password."})
		return
	}
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.clearFailures(req.Email)
	if admin.TOTPEnabled {
		token, err := s.admins.CreateLoginChallenge(r.Context(), admin.ID)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		s.setLoginCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]any{"totp_required": true})
		return
	}
	s.startSession(w, r, admin)
}

func (s *Server) handleAuthTOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console login is not available"})
		return
	}
	cookie, err := r.Cookie(loginCookie)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Sign in again."})
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter the authentication code."})
		return
	}
	admin, err := s.admins.ConsumeLoginChallenge(r.Context(), cookie.Value)
	s.clearCookie(w, loginCookie, "/")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Sign in again."})
		return
	}
	if err := s.admins.VerifySecondFactor(r.Context(), admin.ID, req.Code); err != nil {
		token, challengeErr := s.admins.CreateLoginChallenge(r.Context(), admin.ID)
		if challengeErr == nil {
			s.setLoginCookie(w, token)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That code is not valid."})
		return
	}
	s.startSession(w, r, admin)
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console login is not available"})
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter an email address."})
		return
	}
	if s.tooManyAttempts(r, "reset") || s.tooManyAttempts(r, "reset:"+req.Email) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many attempts. Try again later."})
		return
	}
	s.noteFailure(r, "reset")
	s.noteFailure(r, "reset:"+req.Email)
	if s.sendReset == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Password reset email is not configured."})
		return
	}
	email, err := auth.NormalizeEmail(req.Email)
	if err == nil {
		token, resetErr := s.admins.RequestPasswordReset(r.Context(), email)
		if resetErr != nil {
			writeAdminStoreError(w, resetErr)
			return
		}
		if token != "" {
			if err := s.sendReset(r.Context(), email, resetLink(s.publicURL, token)); err != nil {
				log.Printf("password reset email: %v", err)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.admins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console login is not available"})
		return
	}
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a new password."})
		return
	}
	if s.tooManyAttempts(r, "reset-token") {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many attempts. Try again later."})
		return
	}
	err := s.admins.CompletePasswordReset(r.Context(), req.Token, req.Password)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrPasswordShort):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Use at least 12 characters."})
	case errors.Is(err, auth.ErrResetInvalid):
		s.noteFailure(r, "reset-token")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "That reset link is not valid. Request a new one."})
	default:
		writeAdminStoreError(w, err)
	}
}

func resetLink(publicURL, token string) string {
	return strings.TrimRight(publicURL, "/") + "/login?reset=" + url.QueryEscape(token)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter your current password and a new one."})
		return
	}
	err := s.admins.ChangePassword(r.Context(), admin.ID, req.Current, req.Next)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrBadCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "The current password is wrong."})
	case errors.Is(err, auth.ErrPasswordShort):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Use at least 12 characters."})
	default:
		writeAdminStoreError(w, err)
	}
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	secret, err := s.admins.BeginTOTP(r.Context(), admin.ID)
	if errors.Is(err, auth.ErrTOTPEnabled) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Two-factor authentication is already on."})
		return
	}
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"url":    auth.ProvisioningURI(admin.Email, secret),
	})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter the authentication code."})
		return
	}
	codes, err := s.admins.ConfirmTOTP(r.Context(), admin.ID, req.Code)
	if errors.Is(err, auth.ErrTOTPInvalid) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That code is not valid."})
		return
	}
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter your password and authentication code."})
		return
	}
	err := s.admins.DisableTOTP(r.Context(), admin.ID, req.Password, req.Code)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrBadCredentials), errors.Is(err, auth.ErrTOTPInvalid):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "The password or code is wrong."})
	default:
		writeAdminStoreError(w, err)
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, admin auth.Admin) {
	sessionID, expires, err := s.admins.CreateSession(r.Context(), admin.ID)
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.setSessionCookie(w, sessionID, expires)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"admin":         adminView(admin),
	})
}

func (s *Server) setLoginCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
		MaxAge:   int((5 * time.Minute).Seconds()),
	})
}
