// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"testing"

	"cloud.google.com/go/iam"
)

func TestGCSPolicyPublicRead(t *testing.T) {
	private := &iam.Policy{}
	private.Add("user:a@example.com", "roles/storage.objectViewer")
	if gcsPolicyGrantsPublicRead(private) {
		t.Fatal("a bucket with public access prevention off and no public member is private")
	}

	public := &iam.Policy{}
	public.Add(iam.AllUsers, "roles/storage.objectViewer")
	if !gcsPolicyGrantsPublicRead(public) {
		t.Fatal("expected allUsers object read to be public")
	}

	authenticated := &iam.Policy{}
	authenticated.Add(iam.AllAuthenticatedUsers, "roles/storage.legacyObjectReader")
	if !gcsPolicyGrantsPublicRead(authenticated) {
		t.Fatal("expected allAuthenticatedUsers object read to be public")
	}

	writer := &iam.Policy{}
	writer.Add(iam.AllUsers, "roles/storage.objectCreator")
	if gcsPolicyGrantsPublicRead(writer) {
		t.Fatal("object create is not object read")
	}
}
