// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// policyGrantsS3Bucket reports whether an identity policy allows any s3 action
// on bucket. Deny statements and conditions are not evaluated.
func policyGrantsS3Bucket(document, bucket string) (bool, error) {
	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return false, fmt.Errorf("parse policy: %w", err)
	}
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if len(stmt.NotAction) > 0 || len(stmt.NotResource) > 0 {
			continue
		}
		if !actionsGrantS3(stmt.Action) || !resourcesGrantBucket(stmt.Resource, bucket) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func decodePolicyDocument(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty policy document")
	}
	if json.Valid([]byte(raw)) {
		return raw, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("decode policy document: %w", err)
	}
	if !json.Valid([]byte(decoded)) {
		return "", fmt.Errorf("policy document is not JSON")
	}
	return decoded, nil
}

func actionsGrantS3(actions []string) bool {
	for _, action := range actions {
		if actionGrantsS3(action) {
			return true
		}
	}
	return false
}

func actionGrantsS3(action string) bool {
	action = strings.TrimSpace(action)
	if action == "*" || action == "*:*" {
		return true
	}
	service, _, ok := strings.Cut(action, ":")
	return ok && strings.EqualFold(service, "s3")
}

func resourcesGrantBucket(resources []string, bucket string) bool {
	for _, resource := range resources {
		if resourceGrantsBucket(resource, bucket) {
			return true
		}
	}
	return false
}

func resourceGrantsBucket(pattern, bucket string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" {
		return true
	}
	const marker = ":s3:::"
	i := strings.Index(pattern, marker)
	if i < 0 {
		return false
	}
	rest := pattern[i+len(marker):]
	bucketPattern, _, _ := strings.Cut(rest, "/")
	if bucketPattern == "" {
		return false
	}
	ok, err := path.Match(bucketPattern, bucket)
	return err == nil && ok
}

type policyDocument struct {
	Statement statementList `json:"Statement"`
}

type statementList []policyStatement

func (s *statementList) UnmarshalJSON(data []byte) error {
	data = bytesTrim(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '{' {
		var one policyStatement
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		*s = []policyStatement{one}
		return nil
	}
	var many []policyStatement
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type policyStatement struct {
	Effect      string       `json:"Effect"`
	Action      stringOrList `json:"Action"`
	NotAction   stringOrList `json:"NotAction"`
	Resource    stringOrList `json:"Resource"`
	NotResource stringOrList `json:"NotResource"`
}

type stringOrList []string

func (s *stringOrList) UnmarshalJSON(data []byte) error {
	data = bytesTrim(data)
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	if data[0] == '"' {
		var one string
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func bytesTrim(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}
