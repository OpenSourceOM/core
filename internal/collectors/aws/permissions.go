// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

// ReadPermissions are the IAM actions om scan aws uses. The inventory role
// grants these and nothing that creates or deletes a resource.
var ReadPermissions = []string{
	"cloudtrail:LookupEvents",
	"ec2:DescribeInstances",
	"ec2:DescribeSecurityGroups",
	"iam:GetAccessKeyLastUsed",
	"iam:GetInstanceProfile",
	"iam:GetPolicy",
	"iam:GetPolicyVersion",
	"iam:GetRolePolicy",
	"iam:GetUserPolicy",
	"iam:ListAccessKeys",
	"iam:ListAttachedRolePolicies",
	"iam:ListAttachedUserPolicies",
	"iam:ListMFADevices",
	"iam:ListRolePolicies",
	"iam:ListRoles",
	"iam:ListUserPolicies",
	"iam:ListUsers",
	"rds:DescribeDBInstances",
	"s3:GetBucketAcl",
	"s3:GetBucketPolicy",
	"s3:GetBucketPublicAccessBlock",
	"s3:GetBucketTagging",
	"s3:GetBucketVersioning",
	"s3:GetEncryptionConfiguration",
	"s3:ListAllMyBuckets",
}
