// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
)

func TestAssumeRoleOptions(t *testing.T) {
	withID := stscreds.AssumeRoleOptions{}
	assumeRoleOptions("external-id")(&withID)
	if withID.RoleSessionName != assumeRoleSession {
		t.Fatalf("session = %q", withID.RoleSessionName)
	}
	if aws.ToString(withID.ExternalID) != "external-id" {
		t.Fatalf("external id = %q", aws.ToString(withID.ExternalID))
	}

	without := stscreds.AssumeRoleOptions{}
	assumeRoleOptions("  ")(&without)
	if without.ExternalID != nil {
		t.Fatal("blank external id should be omitted")
	}
}

func TestReadPermissionsStayReadOnly(t *testing.T) {
	for _, action := range ReadPermissions {
		switch {
		case action == "ec2:CreateSnapshot", action == "ec2:AttachVolume", action == "iam:CreateRole":
			t.Fatalf("read list grants %s", action)
		}
	}
	if len(ReadPermissions) < 20 {
		t.Fatalf("permissions = %d", len(ReadPermissions))
	}
}
