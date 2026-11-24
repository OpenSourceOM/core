// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/connect"
	"github.com/OpenSourceOM/core/internal/graph"
)

type memoryConnections struct {
	items map[string]graph.CloudConnection
}

func (m *memoryConnections) ListCloudConnections(context.Context) ([]graph.CloudConnection, error) {
	out := make([]graph.CloudConnection, 0, len(m.items))
	for _, item := range m.items {
		out = append(out, item)
	}
	return out, nil
}

func (m *memoryConnections) GetCloudConnection(_ context.Context, id string) (graph.CloudConnection, error) {
	item, ok := m.items[id]
	if !ok {
		return graph.CloudConnection{}, graph.ErrCloudConnectionNotFound
	}
	return item, nil
}

func (m *memoryConnections) InsertCloudConnection(_ context.Context, conn graph.CloudConnection) error {
	if m.items == nil {
		m.items = map[string]graph.CloudConnection{}
	}
	m.items[conn.ID] = conn
	return nil
}

func (m *memoryConnections) UpdateCloudConnection(_ context.Context, conn graph.CloudConnection) error {
	if _, ok := m.items[conn.ID]; !ok {
		return graph.ErrCloudConnectionNotFound
	}
	m.items[conn.ID] = conn
	return nil
}

func (m *memoryConnections) DeleteCloudConnection(_ context.Context, id string) error {
	if _, ok := m.items[id]; !ok {
		return graph.ErrCloudConnectionNotFound
	}
	delete(m.items, id)
	return nil
}

func TestCreateConnectionRejectsAnAccessKey(t *testing.T) {
	store := &memoryConnections{}
	server := &Server{connections: store}
	body := bytes.NewBufferString(`{"provider":"aws"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/connect/connections", body)
	server.handleCreateConnection(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d %s", recorder.Code, recorder.Body.String())
	}
	var created connect.Setup
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Connection.ExternalID == "" || !strings.Contains(created.Links[0].URL, "cloudformation") {
		t.Fatalf("%+v", created)
	}

	patch := created.Connection
	patch.InventoryRoleARN = "AKIAIOSFODNN7EXAMPLE"
	raw, _ := json.Marshal(patch)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPatch, "/v1/connect/connections/"+patch.ID, bytes.NewReader(raw))
	request.SetPathValue("id", patch.ID)
	server.handleUpdateConnection(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("patch status = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestVerifyConnectionUsesTheStub(t *testing.T) {
	conn, err := connect.New("aws", "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryConnections{items: map[string]graph.CloudConnection{conn.ID: conn}}
	server := &Server{
		connections: store,
		verifyCloud: func(context.Context, graph.CloudConnection, string) (connect.Identity, error) {
			return connect.Identity{Provider: "aws", AccountID: "123456789012", Principal: "arn:aws:iam::123456789012:role/opensourceom-inventory", Target: "inventory"}, nil
		},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/connect/connections/"+conn.ID+"/verify", strings.NewReader(`{"target":"inventory"}`))
	request.SetPathValue("id", conn.ID)
	server.handleVerifyConnection(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d %s", recorder.Code, recorder.Body.String())
	}
	saved := store.items[conn.ID]
	if saved.AccountID != "123456789012" {
		t.Fatalf("account = %s", saved.AccountID)
	}
}

func TestScanConnectionSavesTheBatch(t *testing.T) {
	conn, err := connect.New("gcp", "")
	if err != nil {
		t.Fatal(err)
	}
	conn.AccountID = "demo-project"
	store := &memoryConnections{items: map[string]graph.CloudConnection{conn.ID: conn}}
	var saved int
	server := &Server{
		connections: store,
		scanCloud: func(context.Context, graph.CloudConnection) (graph.Batch, []graph.Scope, string, error) {
			return graph.Batch{Nodes: []graph.Node{{ID: "n"}}}, []graph.Scope{{AccountID: "demo-project"}}, "GCP project demo-project", nil
		},
		saveGraph: func(context.Context, []graph.Scope, graph.Batch) error {
			saved++
			return nil
		},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/connect/connections/"+conn.ID+"/scan", nil)
	request.SetPathValue("id", conn.ID)
	server.handleScanConnection(recorder, request)
	if recorder.Code != http.StatusOK || saved != 1 {
		t.Fatalf("status = %d saved = %d %s", recorder.Code, saved, recorder.Body.String())
	}
}

func TestTemplateDownloadIsTheInventoryRole(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/connect/templates/aws-inventory", nil)
	request.SetPathValue("name", "aws-inventory")
	server.handleConnectTemplate(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "opensourceom-inventory") {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "ec2:CreateSnapshot") {
		t.Fatal("inventory template grants snapshot creation")
	}
}
