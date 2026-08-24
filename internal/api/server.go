// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/export"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/internal/rules"
)

type Server struct {
	store     *graph.Store
	querier   *graph.Querier
	rules     *rules.Engine
	apiSecret string
}

func NewServer(store *graph.Store, apiSecret string) *Server {
	return &Server{
		store:     store,
		querier:   graph.NewQuerier(store),
		rules:     rules.NewEngine(store),
		apiSecret: apiSecret,
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
	mux.Handle("/", uiHandler())
	mux.Handle("/ui/", http.StripPrefix("/ui/", uiHandler()))
	return mux
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
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "opensourceom-api",
	})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var batch graph.Batch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	if err := s.store.UpsertBatch(r.Context(), batch); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	ruleID := r.URL.Query().Get("id")
	var result rules.RunResult
	var err error
	if ruleID == "" {
		result, err = s.rules.RunAll(r.Context())
	} else {
		result, err = s.rules.Run(r.Context(), ruleID)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		identityID = node.ID
	}
	result, err := s.store.BlastRadius(r.Context(), identityID, 6)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportSlack(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	webhook := r.URL.Query().Get("webhook")
	if webhook == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "webhook query parameter required"})
		return
	}
	records, err := export.LoadFindingRecords(r.Context(), s.store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := export.PostSlack(r.Context(), webhook, records); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exported": len(records)})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodeType := r.URL.Query().Get("type")
	limit := queryLimit(r, 500)
	nodes, err := s.store.ListNodes(r.Context(), nodeType, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleEdges(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r, 2000)
	edges, err := s.store.ListEdges(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, edges)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context(), "", queryLimit(r, 500))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	edges, err := s.store.ListEdges(r.Context(), queryLimit(r, 2000))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, graph.GraphSnapshot{Nodes: nodes, Edges: edges})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListFindings(r.Context(), queryLimit(r, 200))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func queryLimit(r *http.Request, fallback int) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return fallback
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return fallback
	}
	return limit
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing query parameter name"})
		return
	}

	result, err := s.querier.Run(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authorize(r *http.Request) bool {
	if s.apiSecret == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ") == s.apiSecret
	}
	return r.Header.Get("X-API-Key") == s.apiSecret
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
