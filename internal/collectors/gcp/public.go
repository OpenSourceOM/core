// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import "cloud.google.com/go/iam"

func gcsPolicyGrantsPublicRead(policy *iam.Policy) bool {
	if policy == nil {
		return false
	}
	for _, role := range policy.Roles() {
		if !gcsRoleAllowsObjectRead(role) {
			continue
		}
		for _, member := range policy.Members(role) {
			if member == iam.AllUsers || member == iam.AllAuthenticatedUsers {
				return true
			}
		}
	}
	return false
}

func gcsRoleAllowsObjectRead(role iam.RoleName) bool {
	switch role {
	case iam.Owner, iam.Editor, iam.Viewer,
		"roles/storage.admin",
		"roles/storage.objectAdmin",
		"roles/storage.objectViewer",
		"roles/storage.legacyBucketOwner",
		"roles/storage.legacyObjectOwner",
		"roles/storage.legacyObjectReader":
		return true
	default:
		return false
	}
}
