// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"strings"
	"testing"
)

func TestNewRejectsSecretsAndUnknownClouds(t *testing.T) {
	if _, err := New("digitalocean", ""); err == nil {
		t.Fatal("expected an error")
	}
	conn, err := New("aws", "")
	if err != nil {
		t.Fatal(err)
	}
	conn.InventoryRoleARN = "AKIAIOSFODNN7EXAMPLE"
	if err := Validate(conn); err == nil {
		t.Fatal("access key was accepted")
	}
	conn.InventoryRoleARN = "arn:aws:iam::123456789012:role/opensourceom-inventory"
	conn.ScannerAccountID = "123456789012"
	if err := Validate(conn); err != nil {
		t.Fatal(err)
	}
}

func TestAWSSetupLinkCarriesExternalID(t *testing.T) {
	conn, err := New("aws", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	conn.InventoryPrincipal = "arn:aws:iam::123456789012:role/opensourceom-worker"
	conn.ScannerPrincipal = conn.InventoryPrincipal
	conn.ScannerAccountID = "123456789012"
	if err := Validate(conn); err != nil {
		t.Fatal(err)
	}
	setup, err := Present(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.Steps) < 4 {
		t.Fatalf("steps = %d", len(setup.Steps))
	}
	if len(setup.Links) != 3 {
		t.Fatalf("links = %d", len(setup.Links))
	}
	inventory := setup.Links[0]
	if !strings.Contains(inventory.URL, "templateURL=") || !strings.Contains(inventory.URL, urlEscape(conn.ExternalID)) && !strings.Contains(inventory.URL, conn.ExternalID) {
		t.Fatalf("inventory url = %s", inventory.URL)
	}
	if !strings.Contains(inventory.URL, "us-west-2") {
		t.Fatalf("region missing: %s", inventory.URL)
	}
	if !strings.Contains(setup.WorkloadCommand, conn.ExternalID) {
		t.Fatalf("command = %s", setup.WorkloadCommand)
	}
	if strings.Contains(strings.ToLower(setup.WorkloadCommand), "akia") {
		t.Fatal(setup.WorkloadCommand)
	}
}

func TestAzureScriptFillsSubscription(t *testing.T) {
	conn, err := New("azure", "")
	if err != nil {
		t.Fatal(err)
	}
	conn.AccountID = "11111111-1111-1111-1111-111111111111"
	conn.InventoryPrincipal = "22222222-2222-2222-2222-222222222222"
	setup, err := Present(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.Links) != 3 || !strings.Contains(setup.Links[0].Script, "export AZURE_SUBSCRIPTION_ID='11111111-1111-1111-1111-111111111111'") {
		t.Fatalf("script = %q", setup.Links[0].Script)
	}
	if !strings.Contains(setup.Links[0].Script, "Reader") {
		t.Fatal("inventory script missing Reader")
	}
}

func TestApplyKeepsExternalID(t *testing.T) {
	current, err := New("gcp", "")
	if err != nil {
		t.Fatal(err)
	}
	next := current
	next.ExternalID = "not-the-generated-id"
	next.AccountID = "demo-project"
	next.InventoryPrincipal = "user:ada@example.com"
	got, err := Apply(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExternalID != current.ExternalID || got.AccountID != "demo-project" {
		t.Fatalf("%+v", got)
	}
}

func urlEscape(value string) string {
	return value
}

func TestGCPMemberRejectsAKey(t *testing.T) {
	conn, err := New("gcp", "us-central1")
	if err != nil {
		t.Fatal(err)
	}
	conn.InventoryPrincipal = "{\n\"private_key\": \"secret\"}"
	if err := Validate(conn); err == nil {
		t.Fatal("private key was accepted")
	}
}
