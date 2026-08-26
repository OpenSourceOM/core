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

func s3PublicAccessFlags(configured, fullyBlocked bool) (block string, public bool) {
	if configured && fullyBlocked {
		return "enabled", false
	}
	return "disabled", true
}

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
