// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func instanceHasPublicIP(instance ec2types.Instance) bool {
	return aws.ToString(instance.PublicIpAddress) != ""
}

func instanceIMDSv2Required(instance ec2types.Instance) bool {
	return instance.MetadataOptions != nil && instance.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired
}

func s3PublicAccessBlock(configured, fullyBlocked bool) string {
	if configured && fullyBlocked {
		return "enabled"
	}
	return "disabled"
}

func instanceInternetReachable(instance ec2types.Instance, groups []ec2types.SecurityGroup) bool {
	if !instanceHasPublicIP(instance) {
		return false
	}
	for _, sg := range groups {
		if securityGroupAllowsInternetIngress(sg) {
			return true
		}
	}
	return false
}

func s3ACLGrantsAnonymousRead(grants []s3types.Grant) bool {
	for _, grant := range grants {
		if grant.Grantee == nil {
			continue
		}
		uri := aws.ToString(grant.Grantee.URI)
		if uri != s3AllUsersURI && uri != s3AuthenticatedUsersURI {
			continue
		}
		switch grant.Permission {
		case s3types.PermissionRead, s3types.PermissionFullControl:
			return true
		}
	}
	return false
}

const (
	s3AllUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	s3AuthenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

func s3EncryptionEnabled(out *s3.GetBucketEncryptionOutput) bool {
	return out != nil && out.ServerSideEncryptionConfiguration != nil &&
		len(out.ServerSideEncryptionConfiguration.Rules) > 0
}

func s3VersioningEnabled(out *s3.GetBucketVersioningOutput) bool {
	return out != nil && out.Status == s3types.BucketVersioningStatusEnabled
}

func unusedAccessKeys(keys []iamtypes.AccessKeyMetadata, lastUsed map[string]*time.Time, maxAge time.Duration) bool {
	now := time.Now()
	for _, key := range keys {
		if key.Status != iamtypes.StatusTypeActive {
			continue
		}
		id := aws.ToString(key.AccessKeyId)
		usedAt, ok := lastUsed[id]
		if !ok || usedAt == nil {
			return true
		}
		if now.Sub(*usedAt) > maxAge {
			return true
		}
	}
	return false
}
