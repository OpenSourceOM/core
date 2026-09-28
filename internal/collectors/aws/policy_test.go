// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import "testing"

func TestPolicyGrantsS3Bucket(t *testing.T) {
	tests := []struct {
		name   string
		doc    string
		bucket string
		want   bool
	}{
		{
			name:   "administrator access",
			doc:    `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
			bucket: "logs",
			want:   true,
		},
		{
			name:   "s3 star on every bucket",
			doc:    `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			bucket: "logs",
			want:   true,
		},
		{
			name:   "get object on one bucket",
			doc:    `{"Statement":{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::logs","arn:aws:s3:::logs/*"]}}`,
			bucket: "logs",
			want:   true,
		},
		{
			name:   "get object on a different bucket",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}}`,
			bucket: "logs",
			want:   false,
		},
		{
			name:   "wildcard bucket prefix",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::acme-*/*"}}`,
			bucket: "acme-logs",
			want:   true,
		},
		{
			name:   "govcloud bucket arn",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws-us-gov:s3:::logs/*"}}`,
			bucket: "logs",
			want:   true,
		},
		{
			name:   "all buckets object wildcard",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*/*"}}`,
			bucket: "logs",
			want:   true,
		},
		{
			name:   "deny is ignored",
			doc:    `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`,
			bucket: "logs",
			want:   false,
		},
		{
			name:   "not resource is skipped",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::other/*"}}`,
			bucket: "logs",
			want:   false,
		},
		{
			name:   "ec2 action does not grant s3",
			doc:    `{"Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`,
			bucket: "logs",
			want:   false,
		},
		{
			name:   "allow with condition still counts",
			doc:    `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}}`,
			bucket: "logs",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policyGrantsS3Bucket(tt.doc, tt.bucket)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("policyGrantsS3Bucket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyGrantsAdmin(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "star on star",
			doc:  `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
			want: true,
		},
		{
			name: "star colon star",
			doc:  `{"Statement":{"Effect":"Allow","Action":"*:*","Resource":["*"]}}`,
			want: true,
		},
		{
			name: "star among other actions",
			doc:  `{"Statement":{"Effect":"Allow","Action":["s3:*","*"],"Resource":"*"}}`,
			want: true,
		},
		{
			name: "iam star is not full admin",
			doc:  `{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`,
			want: false,
		},
		{
			name: "star on one bucket",
			doc:  `{"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::logs"}}`,
			want: false,
		},
		{
			name: "not action is not full admin",
			doc:  `{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`,
			want: false,
		},
		{
			name: "condition is not full admin",
			doc:  `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`,
			want: false,
		},
		{
			name: "deny is ignored",
			doc:  `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policyGrantsAdmin(tt.doc)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("policyGrantsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAdministratorAccessPolicy(t *testing.T) {
	tests := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:iam::aws:policy/AdministratorAccess", true},
		{"arn:aws-us-gov:iam::aws:policy/AdministratorAccess", true},
		{"arn:aws-cn:iam::aws:policy/AdministratorAccess", true},
		{"arn:aws:iam::111122223333:policy/AdministratorAccess", false},
		{"arn:aws:iam::aws:policy/ReadOnlyAccess", false},
		{"arn:aws:iam::aws:policy/job-function/AdministratorAccess", false},
	}
	for _, tt := range tests {
		if got := isAdministratorAccessPolicy(tt.arn); got != tt.want {
			t.Errorf("isAdministratorAccessPolicy(%q) = %v, want %v", tt.arn, got, tt.want)
		}
	}
}

func TestPolicyGrantsS3BucketRejectsInvalidJSON(t *testing.T) {
	if _, err := policyGrantsS3Bucket(`{"Statement":`, "logs"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDecodePolicyDocument(t *testing.T) {
	raw := `%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3A%2A%22%2C%22Resource%22%3A%22%2A%22%7D%7D`
	decoded, err := decodePolicyDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := policyGrantsS3Bucket(decoded, "logs")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected decoded policy to grant logs")
	}

	plain := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	got, err := decodePolicyDocument(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("plain document changed: %s", got)
	}
}

func TestInstanceProfileName(t *testing.T) {
	got := instanceProfileName("arn:aws:iam::111122223333:instance-profile/app/web-profile")
	if got != "web-profile" {
		t.Fatalf("name = %q", got)
	}
	if instanceProfileName("arn:aws:iam::111122223333:instance-profile/") != "" {
		t.Fatal("expected empty name")
	}
}
