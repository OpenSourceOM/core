// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (s *Scanner) crossAccount() bool { return s.AccountID != "" }

func (s *Scanner) prodAPI() ec2API {
	if s.Prod != nil {
		return s.Prod
	}
	return s.API
}

func (s *Scanner) instanceAPI() ec2API {
	if s.crossAccount() {
		return s.prodAPI()
	}
	return s.API
}

func (s *Scanner) localWorker(ctx context.Context) (ec2types.Instance, error) {
	input := &ec2.DescribeInstancesInput{InstanceIds: []string{s.Worker.InstanceID}}
	for {
		page, err := s.API.DescribeInstances(ctx, input)
		if err != nil {
			return ec2types.Instance{}, fmt.Errorf("describe worker: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, inst := range reservation.Instances {
				if aws.ToString(inst.InstanceId) == s.Worker.InstanceID {
					return inst, nil
				}
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return ec2types.Instance{}, fmt.Errorf("worker %s is not in the scanner account", s.Worker.InstanceID)
		}
		input.NextToken = page.NextToken
	}
}

// stageSnapshot shares a production snapshot with the scanner account and
// copies it there. The returned id is what CreateVolume attaches. cleanup
// deletes the copy and removes the share. The caller deletes the source
// snapshot when the scan created it.
func (s *Scanner) stageSnapshot(ctx context.Context, snapID, owner string) (string, func(), error) {
	if !s.crossAccount() {
		return snapID, nil, nil
	}
	if s.Worker.Region == "" {
		return "", nil, fmt.Errorf("worker region is required to copy the snapshot")
	}
	encrypted, err := s.snapshotEncrypted(ctx, snapID)
	if err != nil {
		return "", nil, err
	}
	if encrypted && s.KMSKeyID == "" {
		return "", nil, fmt.Errorf("snapshot %s is encrypted; set --kms-key to a key in the scanner account", snapID)
	}
	if err := s.shareSnapshot(ctx, snapID, true); err != nil {
		return "", nil, err
	}
	copyID, err := s.copySnapshot(ctx, snapID, encrypted, owner)
	if err != nil {
		s.note(s.shareSnapshot(context.Background(), snapID, false))
		return "", nil, err
	}
	if err := s.waitLocalSnapshot(ctx, copyID); err != nil {
		s.deleteLocalSnapshot(copyID)
		s.note(s.shareSnapshot(context.Background(), snapID, false))
		return "", nil, err
	}
	return copyID, func() {
		s.deleteLocalSnapshot(copyID)
		s.note(s.shareSnapshot(context.Background(), snapID, false))
	}, nil
}

func (s *Scanner) snapshotEncrypted(ctx context.Context, id string) (bool, error) {
	out, err := s.prodAPI().DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{id}})
	if err != nil {
		return false, fmt.Errorf("describe snapshot: %w", err)
	}
	if len(out.Snapshots) == 0 {
		return false, fmt.Errorf("snapshot %s disappeared", id)
	}
	return aws.ToBool(out.Snapshots[0].Encrypted), nil
}

func (s *Scanner) shareSnapshot(ctx context.Context, id string, add bool) error {
	perm := &ec2types.CreateVolumePermissionModifications{}
	user := []ec2types.CreateVolumePermission{{UserId: aws.String(s.AccountID)}}
	if add {
		perm.Add = user
	} else {
		perm.Remove = user
	}
	callCtx := ctx
	if !add {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
	}
	_, err := s.prodAPI().ModifySnapshotAttribute(callCtx, &ec2.ModifySnapshotAttributeInput{
		SnapshotId:             aws.String(id),
		Attribute:              ec2types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: perm,
	})
	if err != nil && !add && isNotFound(err) {
		return nil
	}
	if err != nil {
		if add {
			return fmt.Errorf("share snapshot: %w", err)
		}
		return fmt.Errorf("unshare snapshot %s: %w", id, err)
	}
	return nil
}

func (s *Scanner) copySnapshot(ctx context.Context, sourceID string, encrypted bool, owner string) (string, error) {
	in := &ec2.CopySnapshotInput{
		Description:      aws.String("OpenSourceOM workload package inventory"),
		SourceRegion:     aws.String(s.Worker.Region),
		SourceSnapshotId: aws.String(sourceID),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSnapshot,
			Tags:         scanTags(owner),
		}},
	}
	if encrypted || s.KMSKeyID != "" {
		in.Encrypted = aws.Bool(true)
		in.KmsKeyId = aws.String(s.KMSKeyID)
	}
	out, err := s.API.CopySnapshot(ctx, in)
	if err != nil {
		return "", fmt.Errorf("copy snapshot: %w", err)
	}
	id := aws.ToString(out.SnapshotId)
	if id == "" {
		return "", fmt.Errorf("copy snapshot returned an empty snapshot id")
	}
	return id, nil
}
