// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestInstancePackProperties(t *testing.T) {
	open := ec2types.Instance{
		PublicIpAddress: aws.String("1.2.3.4"),
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
			HttpTokens: ec2types.HttpTokensStateOptional,
		},
	}
	if !instanceHasPublicIP(open) {
		t.Fatal("expected public IP")
	}
	if instanceIMDSv2Required(open) {
		t.Fatal("optional tokens is not IMDSv2-only")
	}

	locked := ec2types.Instance{
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
			HttpTokens: ec2types.HttpTokensStateRequired,
		},
	}
	if instanceHasPublicIP(locked) {
		t.Fatal("did not expect public IP")
	}
	if !instanceIMDSv2Required(locked) {
		t.Fatal("expected IMDSv2 required")
	}
}

func TestS3PublicAccessFlags(t *testing.T) {
	block, public := s3PublicAccessFlags(true, true)
	if block != "enabled" || public {
		t.Fatalf("fully blocked: block=%s public=%v", block, public)
	}
	block, public = s3PublicAccessFlags(true, false)
	if block != "disabled" || !public {
		t.Fatalf("partial block: block=%s public=%v", block, public)
	}
	block, public = s3PublicAccessFlags(false, false)
	if block != "disabled" || !public {
		t.Fatalf("not configured: block=%s public=%v", block, public)
	}
}

func TestS3EncryptionAndVersioning(t *testing.T) {
	if s3EncryptionEnabled(nil) || s3VersioningEnabled(nil) {
		t.Fatal("nil outputs should be disabled")
	}
	if !s3EncryptionEnabled(&s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{}},
		},
	}) {
		t.Fatal("expected encryption when rules exist")
	}
	if !s3VersioningEnabled(&s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled}) {
		t.Fatal("expected versioning enabled")
	}
}

func TestUnusedAccessKeys(t *testing.T) {
	id := "AKIAEXAMPLE"
	keys := []iamtypes.AccessKeyMetadata{{
		AccessKeyId: aws.String(id),
		Status:      iamtypes.StatusTypeActive,
	}}
	if !unusedAccessKeys(keys, map[string]*time.Time{}, 90*24*time.Hour) {
		t.Fatal("never-used key should be unused")
	}
	recent := time.Now().Add(-24 * time.Hour)
	if unusedAccessKeys(keys, map[string]*time.Time{id: &recent}, 90*24*time.Hour) {
		t.Fatal("recently used key should not be unused")
	}
	stale := time.Now().Add(-100 * 24 * time.Hour)
	if !unusedAccessKeys(keys, map[string]*time.Time{id: &stale}, 90*24*time.Hour) {
		t.Fatal("stale key should be unused")
	}
}

func TestSecurityGroupOpenIngress(t *testing.T) {
	sg := ec2types.SecurityGroup{
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}},
	}
	if !securityGroupAllowsInternetIngress(sg) {
		t.Fatal("expected open ingress")
	}
}
