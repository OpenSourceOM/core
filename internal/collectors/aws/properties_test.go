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

func TestS3PublicAccessBlock(t *testing.T) {
	if s3PublicAccessBlock(true, true) != "enabled" {
		t.Fatal("expected a full block to be enabled")
	}
	if s3PublicAccessBlock(true, false) != "disabled" {
		t.Fatal("expected a partial block to be disabled")
	}
	if s3PublicAccessBlock(false, false) != "disabled" {
		t.Fatal("expected a missing block to be disabled")
	}
}

func TestS3PublicAccessGrant(t *testing.T) {
	privateACL := []s3types.Grant{{
		Grantee:    &s3types.Grantee{ID: aws.String("owner")},
		Permission: s3types.PermissionFullControl,
	}}
	if s3ACLGrantsAnonymousRead(privateACL) {
		t.Fatal("owner grant is not anonymous")
	}
	if s3PublicAccessBlock(false, false) != "disabled" {
		t.Fatal("private bucket with no block should still record the block as disabled")
	}

	publicPolicy := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/*"}]}`
	grants, err := s3PolicyGrantsAnonymousRead(publicPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if !grants {
		t.Fatal("expected anonymous GetObject to be public")
	}
	if s3PublicAccessBlock(true, false) != "disabled" {
		t.Fatal("expected the public policy's disabled block to stay disabled")
	}

	accountPolicy := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*"}}`
	grants, err = s3PolicyGrantsAnonymousRead(accountPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if grants {
		t.Fatal("account principal is not anonymous")
	}

	conditional := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}`
	grants, err = s3PolicyGrantsAnonymousRead(conditional)
	if err != nil {
		t.Fatal(err)
	}
	if grants {
		t.Fatal("conditional grant is not public")
	}

	readers := []s3types.Grant{{
		Grantee:    &s3types.Grantee{URI: aws.String(s3AllUsersURI)},
		Permission: s3types.PermissionRead,
	}}
	if !s3ACLGrantsAnonymousRead(readers) {
		t.Fatal("expected AllUsers READ to be public")
	}
	writers := []s3types.Grant{{
		Grantee:    &s3types.Grantee{URI: aws.String(s3AuthenticatedUsersURI)},
		Permission: s3types.PermissionWrite,
	}}
	if s3ACLGrantsAnonymousRead(writers) {
		t.Fatal("WRITE is not anonymous read")
	}
}

func TestInstanceInternetReachable(t *testing.T) {
	open22 := ec2types.SecurityGroup{
		GroupId: aws.String("sg-22"),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}},
	}
	closed := ec2types.SecurityGroup{
		GroupId: aws.String("sg-closed"),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
		}},
	}

	private := ec2types.Instance{
		InstanceId: aws.String("i-private"),
		SecurityGroups: []ec2types.GroupIdentifier{{
			GroupId: aws.String("sg-22"),
		}},
	}
	if instanceInternetReachable(private, []ec2types.SecurityGroup{open22}) {
		t.Fatal("private instance with an open group is not internet-reachable")
	}

	public22 := ec2types.Instance{
		InstanceId:      aws.String("i-ssh"),
		PublicIpAddress: aws.String("1.2.3.4"),
	}
	if !instanceInternetReachable(public22, []ec2types.SecurityGroup{open22}) {
		t.Fatal("public instance with port 22 open to the world should be reachable")
	}

	publicClosed := ec2types.Instance{
		InstanceId:      aws.String("i-closed"),
		PublicIpAddress: aws.String("1.2.3.4"),
	}
	if instanceInternetReachable(publicClosed, []ec2types.SecurityGroup{closed}) {
		t.Fatal("public instance with no world-open group is not reachable")
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
	https := ec2types.SecurityGroup{
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}},
	}
	if !securityGroupAllowsInternetIngress(https) {
		t.Fatal("expected port 443 open to the world")
	}
	ssh := ec2types.SecurityGroup{
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}},
	}
	if !securityGroupAllowsInternetIngress(ssh) {
		t.Fatal("expected port 22 open to the world")
	}
	private := ec2types.SecurityGroup{
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
		}},
	}
	if securityGroupAllowsInternetIngress(private) {
		t.Fatal("rfc1918 ingress is not internet-facing")
	}
}
