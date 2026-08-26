// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestLoadEmbeddedPacks(t *testing.T) {
	rules, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cis-s3-public-access",
		"cis-s3-public-access-block",
		"cis-s3-encryption",
		"cis-s3-versioning",
		"cis-sg-open-ingress",
		"cis-iam-admin",
		"cis-iam-no-mfa",
		"cis-iam-unused-access-keys",
		"cis-ec2-imdsv1",
		"cis-ec2-public-ip",
		"k8s-public-loadbalancer",
	}
	got := make(map[string]bool, len(rules))
	for _, rule := range rules {
		got[rule.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("missing pack rule %s", id)
		}
	}
	if len(Catalog) < len(BuiltinCatalog)+len(want) {
		t.Fatalf("Catalog len = %d, want at least %d", len(Catalog), len(BuiltinCatalog)+len(want))
	}
}

func TestMatchProperties(t *testing.T) {
	have := map[string]any{"public_access": true, "service": "s3", "encryption": false}
	if !matchProperties(have, map[string]any{"public_access": true}) {
		t.Fatal("expected public_access match")
	}
	if matchProperties(have, map[string]any{"encryption": true}) {
		t.Fatal("did not expect encryption match")
	}
	if !matchProperties(have, map[string]any{"service": "s3", "encryption": false}) {
		t.Fatal("expected combined property match")
	}
}

func TestMatchGraph(t *testing.T) {
	yes := true
	no := false
	got := GraphContext{InternetReachable: true, PathToDatastore: false}
	if !matchGraph(got, &GraphMatch{InternetReachable: &yes}) {
		t.Fatal("expected internet_reachable match")
	}
	if matchGraph(got, &GraphMatch{InternetReachable: &no}) {
		t.Fatal("did not expect internet_reachable=false")
	}
}
