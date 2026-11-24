// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	assets "github.com/OpenSourceOM/core/deploy/connect"
	"github.com/OpenSourceOM/core/internal/connect"
	"github.com/OpenSourceOM/core/internal/graph"
)

type cloudConnectionStore interface {
	ListCloudConnections(context.Context) ([]graph.CloudConnection, error)
	GetCloudConnection(context.Context, string) (graph.CloudConnection, error)
	InsertCloudConnection(context.Context, graph.CloudConnection) error
	UpdateCloudConnection(context.Context, graph.CloudConnection) error
	DeleteCloudConnection(context.Context, string) error
}

func (s *Server) cloudStore() (cloudConnectionStore, error) {
	if s.connections != nil {
		return s.connections, nil
	}
	if s.store == nil {
		return nil, errors.New("cloud connect is not available")
	}
	return s.store, nil
}

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	store, err := s.cloudStore()
	if err != nil {
		writeConnectError(w, err)
		return
	}
	rows, err := store.ListCloudConnections(r.Context())
	if err != nil {
		writeConnectError(w, err)
		return
	}
	setups := make([]connect.Setup, 0, len(rows))
	for _, row := range rows {
		setup, err := connect.Present(row)
		if err != nil {
			writeConnectError(w, err)
			return
		}
		setups = append(setups, setup)
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": setups})
}

func (s *Server) handleCreateConnection(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	conn, err := connect.New(body.Provider, body.Region)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	store, err := s.cloudStore()
	if err != nil {
		writeConnectError(w, err)
		return
	}
	if err := store.InsertCloudConnection(r.Context(), conn); err != nil {
		writeConnectError(w, err)
		return
	}
	setup, err := connect.Present(conn)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, setup)
}

func (s *Server) handleUpdateConnection(w http.ResponseWriter, r *http.Request) {
	store, current, ok := s.loadConnection(w, r)
	if !ok {
		return
	}
	var body graph.CloudConnection
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	next, err := connect.Apply(current, body)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	if err := store.UpdateCloudConnection(r.Context(), next); err != nil {
		writeConnectError(w, err)
		return
	}
	setup, err := connect.Present(next)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, setup)
}

func (s *Server) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	store, err := s.cloudStore()
	if err != nil {
		writeConnectError(w, err)
		return
	}
	if err := store.DeleteCloudConnection(r.Context(), r.PathValue("id")); err != nil {
		writeConnectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleVerifyConnection(w http.ResponseWriter, r *http.Request) {
	store, current, ok := s.loadConnection(w, r)
	if !ok {
		return
	}
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	verify := s.verifyCloud
	if verify == nil {
		verify = connect.Verify
	}
	identity, err := verify(ctx, current, body.Target)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	if identity.Target == "inventory" && identity.AccountID != "" && identity.AccountID != current.AccountID {
		current.AccountID = identity.AccountID
		if err := store.UpdateCloudConnection(ctx, current); err != nil {
			writeConnectError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, identity)
}

func (s *Server) handleScanConnection(w http.ResponseWriter, r *http.Request) {
	_, current, ok := s.loadConnection(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	scan := s.scanCloud
	if scan == nil {
		scan = connect.Inventory
	}
	batch, scopes, label, err := scan(ctx, current)
	if err != nil {
		writeConnectError(w, err)
		return
	}
	if err := s.saveInventory(ctx, scopes, batch); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the scan"})
		return
	}
	accountID := current.AccountID
	if len(scopes) > 0 && scopes[0].AccountID != "" {
		accountID = scopes[0].AccountID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":      len(batch.Nodes),
		"edges":      len(batch.Edges),
		"label":      label,
		"account_id": accountID,
	})
}

func (s *Server) handleConnectTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body, err := assets.ReadTemplate(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Unknown template."})
		return
	}
	filename := path.Base(assets.TemplateFiles[name])
	contentType := "text/yaml; charset=utf-8"
	if strings.HasSuffix(filename, ".sh") {
		contentType = "text/x-shellscript; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) loadConnection(w http.ResponseWriter, r *http.Request) (cloudConnectionStore, graph.CloudConnection, bool) {
	store, err := s.cloudStore()
	if err != nil {
		writeConnectError(w, err)
		return nil, graph.CloudConnection{}, false
	}
	current, err := store.GetCloudConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		writeConnectError(w, err)
		return nil, graph.CloudConnection{}, false
	}
	return store, current, true
}

func (s *Server) saveInventory(ctx context.Context, scopes []graph.Scope, batch graph.Batch) error {
	if s.saveGraph != nil {
		return s.saveGraph(ctx, scopes, batch)
	}
	if s.store == nil {
		return errors.New("graph store is not available")
	}
	return s.store.ReplaceInventory(ctx, scopes, batch)
}

func writeConnectError(w http.ResponseWriter, err error) {
	var invalid *connect.Invalid
	if errors.As(err, &invalid) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": invalid.Error()})
		return
	}
	if errors.Is(err, graph.ErrCloudConnectionNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "That cloud connection is gone."})
		return
	}
	var cloud *connect.CloudError
	if errors.As(err, &cloud) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": cloud.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the connection"})
}
