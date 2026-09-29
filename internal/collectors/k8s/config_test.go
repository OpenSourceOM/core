// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := []byte(`apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://prod.example.com
- name: other
  cluster:
    server: https://other.example.com
contexts:
- name: prod
  context:
    cluster: prod
    user: u
- name: other
  context:
    cluster: other
    user: u
current-context: other
users:
- name: u
  user:
    token: t
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigUsesNamedContext(t *testing.T) {
	t.Setenv("KUBECONFIG", writeKubeconfig(t))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	cfg, err := NewCollector("prod", "apps").loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "https://prod.example.com" {
		t.Fatalf("host = %q", cfg.Host)
	}
}

func TestLoadConfigDefaultClusterKeepsCurrentContext(t *testing.T) {
	t.Setenv("KUBECONFIG", writeKubeconfig(t))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	cfg, err := NewCollector("default", "").loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "https://other.example.com" {
		t.Fatalf("host = %q", cfg.Host)
	}
}

func TestLoadConfigKubeconfigWinsInsideCluster(t *testing.T) {
	t.Setenv("KUBECONFIG", writeKubeconfig(t))
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	cfg, err := NewCollector("prod", "").loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "https://prod.example.com" {
		t.Fatalf("host = %q", cfg.Host)
	}
}

func TestLoadConfigInClusterIgnoresContextName(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	_, err := NewCollector("prod", "apps").loadConfig()
	if err == nil {
		t.Fatal("expected in-cluster config to fail without a service account token")
	}
	if strings.Contains(err.Error(), "context") {
		t.Fatalf("cluster name was used as a kubeconfig context: %v", err)
	}
	if !strings.Contains(err.Error(), "serviceaccount") {
		t.Fatalf("expected in-cluster error, got %v", err)
	}
}
