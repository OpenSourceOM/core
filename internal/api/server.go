// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/OpenSourceOM/core/internal/auth"
	"github.com/OpenSourceOM/core/internal/export"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/rules"
)

const (
	schemaNotReadyCode    = "schema_not_ready"
	schemaNotReadyMessage = "The graph database has not been initialized. Run om migrate, then refresh this page."
)

type Server struct {
	store         *graph.Store
	health        healthChecker
	querier       *graph.Querier
	rules         *rules.Engine
	admins        auth.Directory
	publicURL     string
	providers     map[string]auth.Provider
	setupEmail    string
	sendPassword  func(ctx context.Context, to, password string) error
	sendReset     func(ctx context.Context, to, resetURL string) error
	loginLimit    *loginLimiter
	secureCookies bool
}

type healthChecker interface {
	Ping(context.Context) error
}

func NewServer(store *graph.Store) *Server {
	return &Server{
		store:   store,
		health:  store,
		querier: graph.NewQuerier(store),
		rules:   rules.NewEngine(store),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/ingest", s.handleIngest)
	mux.HandleFunc("GET /v1/graph/stats", s.handleStats)
	mux.HandleFunc("GET /v1/graph/query", s.handleQuery)
	mux.HandleFunc("GET /v1/graph/queries", s.handleQueryList)
	mux.HandleFunc("GET /v1/graph/nodes", s.handleNodes)
	mux.HandleFunc("GET /v1/graph/edges", s.handleEdges)
	mux.HandleFunc("GET /v1/graph/snapshot", s.handleSnapshot)
	mux.HandleFunc("GET /v1/findings", s.handleFindings)
	mux.HandleFunc("GET /v1/rules", s.handleRulesList)
	mux.HandleFunc("POST /v1/rules/run", s.handleRulesRun)
	mux.HandleFunc("GET /v1/identity/blast-radius", s.handleBlastRadius)
	mux.HandleFunc("POST /v1/export/slack", s.handleExportSlack)
	mux.HandleFunc("GET /v1/auth/session", s.handleAuthSession)
	mux.HandleFunc("POST /v1/auth/setup", s.handleAuthSetup)
	mux.HandleFunc("POST /v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /v1/auth/totp", s.handleAuthTOTP)
	mux.HandleFunc("POST /v1/auth/password", s.handleChangePassword)
	mux.HandleFunc("POST /v1/auth/forgot", s.handleForgotPassword)
	mux.HandleFunc("POST /v1/auth/reset", s.handleResetPassword)
	mux.HandleFunc("POST /v1/auth/totp/setup", s.handleTOTPSetup)
	mux.HandleFunc("POST /v1/auth/totp/confirm", s.handleTOTPConfirm)
	mux.HandleFunc("POST /v1/auth/totp/disable", s.handleTOTPDisable)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/admins", s.handleListAdmins)
	mux.HandleFunc("POST /v1/admins", s.handleCreateAdmin)
	mux.HandleFunc("POST /v1/admins/token", s.handleCreateToken)
	mux.HandleFunc("POST /v1/admins/token/rotate", s.handleRotateToken)
	mux.HandleFunc("DELETE /v1/admins/{id}", s.handleDeleteAdmin)
	mux.HandleFunc("GET /auth/{provider}/start", s.handleAuthStart)
	mux.HandleFunc("GET /auth/{provider}/callback", s.handleAuthCallback)
	mux.HandleFunc("GET /login", handleConsolePage)
	mux.Handle("/", uiHandler())
	mux.Handle("/ui/", http.StripPrefix("/ui/", uiHandler()))
	return s.requireAPIAuth(mux)
}

// requireAPIAuth demands a console session or that admin's API token on every
// /v1 route except the public auth routes in publicV1. The HTML stays
// open so the login page can load. Admin management still requires a session.
func (s *Server) requireAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicV1(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			if admin, ok := s.currentAdmin(r); ok {
				if admin.MustChangePassword && r.URL.Path != "/v1/auth/password" {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "Choose a new password before using the console."})
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if !s.authorize(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ListenAndServe(addr string) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("api listening on %s", addr)
	return server.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.health.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status":  "unavailable",
			"service": "opensourceom-api",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "opensourceom-api",
	})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var batch graph.Batch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	if err := s.store.UpsertBatch(r.Context(), batch); err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"nodes_ingested": len(batch.Nodes),
		"edges_ingested": len(batch.Edges),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleQueryList(w http.ResponseWriter, r *http.Request) {
	type queryEntry struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	entries := make([]queryEntry, 0, len(graph.NamedQueries))
	for name, description := range graph.NamedQueries {
		entries = append(entries, queryEntry{Name: name, Description: description})
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": entries})
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
	type ruleEntry struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	entries := make([]ruleEntry, 0, len(rules.Catalog))
	for _, rule := range rules.Catalog {
		entries = append(entries, ruleEntry{ID: rule.ID, Name: rule.Name, Description: rule.Description})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": entries})
}

func (s *Server) handleRulesRun(w http.ResponseWriter, r *http.Request) {
	ruleID := r.URL.Query().Get("id")
	var result rules.RunResult
	var err error
	if ruleID == "" {
		result, err = s.rules.RunAll(r.Context())
	} else {
		result, err = s.rules.Run(r.Context(), ruleID)
	}
	if err != nil {
		writeFailure(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	identityID := r.URL.Query().Get("identity_id")
	if identityID == "" {
		name := r.URL.Query().Get("name")
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "identity_id or name required"})
			return
		}
		node, err := s.store.FindIdentityByName(r.Context(), name)
		if err != nil {
			writeFailure(w, err, http.StatusBadRequest)
			return
		}
		identityID = node.ID
	}
	result, err := s.store.BlastRadius(r.Context(), identityID, 6)
	if err != nil {
		writeFailure(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportSlack(w http.ResponseWriter, r *http.Request) {
	webhook, err := slackWebhookFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	records, err := export.LoadFindingRecords(r.Context(), s.store)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	if err := export.PostSlack(r.Context(), webhook, records); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"exported": len(records)})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	limit, err := parsePageLimit(r.URL.Query().Get("limit"), graph.MaxNodePageSize, graph.MaxNodePageSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	page, err := s.store.ListNodes(r.Context(), r.URL.Query().Get("type"), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleEdges(w http.ResponseWriter, r *http.Request) {
	limit, err := parsePageLimit(r.URL.Query().Get("limit"), graph.MaxEdgePageSize, graph.MaxEdgePageSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	page, err := s.store.ListEdges(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	nodeLimit, err := parsePageLimit(r.URL.Query().Get("limit"), graph.MaxNodePageSize, graph.MaxNodePageSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	edgeLimit, err := parsePageLimit(r.URL.Query().Get("edge_limit"), graph.MaxEdgePageSize, graph.MaxEdgePageSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	nodes, err := s.store.ListNodes(r.Context(), "", nodeLimit, r.URL.Query().Get("node_cursor"))
	if err != nil {
		writeListError(w, err)
		return
	}
	edges, err := s.store.ListEdges(r.Context(), edgeLimit, r.URL.Query().Get("edge_cursor"))
	if err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, graph.GraphSnapshot{
		Nodes:           nodes.Nodes,
		Edges:           edges.Edges,
		NextNodesCursor: nodes.NextCursor,
		NextEdgesCursor: edges.NextCursor,
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	limit, err := parsePageLimit(r.URL.Query().Get("limit"), graph.MaxFindingPageSize, graph.MaxFindingPageSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	page, err := s.store.ListFindings(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func parsePageLimit(raw string, fallback, max int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("limit must be a positive integer")
	}
	if limit > max {
		return 0, fmt.Errorf("limit must be at most %d", max)
	}
	return limit, nil
}

func writeListError(w http.ResponseWriter, err error) {
	if errors.Is(err, graph.ErrInvalidCursor) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeStoreError(w, err)
}

func writeStoreError(w http.ResponseWriter, err error) {
	writeFailure(w, err, http.StatusInternalServerError)
}

func writeFailure(w http.ResponseWriter, err error, status int) {
	if isSchemaNotReady(err) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": schemaNotReadyMessage,
			"code":  schemaNotReadyCode,
		})
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// isSchemaNotReady reports a missing graph table, which is what Postgres
// returns when om migrate has not been applied.
func isSchemaNotReady(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing query parameter name"})
		return
	}

	result, err := s.querier.Run(r.Context(), name)
	if err != nil {
		writeFailure(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authorize(r *http.Request) bool {
	if _, ok := s.currentAdmin(r); ok {
		return true
	}
	token := presentedSecret(r)
	if token == "" || s.admins == nil {
		return false
	}
	admin, err := s.admins.AdminForToken(r.Context(), token)
	return err == nil && !admin.MustChangePassword
}

func presentedSecret(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fmt.Fprintf(w, `{"error":"encode failed"}`)
	}
}

func Ping(ctx context.Context, store *graph.Store) error {
	_, err := store.Stats(ctx)
	return err
}

func slackWebhookFromRequest(r *http.Request) (string, error) {
	if r.URL.Query().Has("webhook") {
		return "", fmt.Errorf("webhook query parameter is not allowed")
	}

	var req struct {
		Webhook string `json:"webhook"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", fmt.Errorf("invalid request body")
	}
	if req.Webhook == "" {
		return "", fmt.Errorf("webhook required")
	}

	return req.Webhook, nil
}
