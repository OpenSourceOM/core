// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
)

// Invalid is a rejected connect form. The API returns it as a 400.
type Invalid struct {
	Message string
}

func (e *Invalid) Error() string {
	return e.Message
}

// CloudError is a failure from AWS, Azure, or GCP. The API returns it as a 502.
type CloudError struct {
	Err error
}

func (e *CloudError) Error() string {
	if e == nil || e.Err == nil {
		return "cloud request failed"
	}
	return e.Err.Error()
}

func (e *CloudError) Unwrap() error { return e.Err }

// New starts a connection. The external id is generated here and is not taken from the client.
func New(provider, region string) (graph.CloudConnection, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aws", "azure", "gcp":
	default:
		return graph.CloudConnection{}, &Invalid{Message: "Choose AWS, Azure, or GCP."}
	}
	externalID, err := randomHex(16)
	if err != nil {
		return graph.CloudConnection{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return graph.CloudConnection{}, err
	}
	conn := graph.CloudConnection{
		ID:            id,
		Provider:      provider,
		Region:        strings.TrimSpace(region),
		ExternalID:    externalID,
		ResourceGroup: "opensourceom-scanner",
	}
	normalize(&conn)
	if err := Validate(conn); err != nil {
		return graph.CloudConnection{}, err
	}
	return conn, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Apply keeps the id, provider, and external id, and replaces the fields the form edits.
func Apply(current, next graph.CloudConnection) (graph.CloudConnection, error) {
	next.ID = current.ID
	next.Provider = current.Provider
	next.ExternalID = current.ExternalID
	normalize(&next)
	if err := Validate(next); err != nil {
		return graph.CloudConnection{}, err
	}
	return next, nil
}
