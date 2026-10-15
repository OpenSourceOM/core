// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// Permissions are the IAM actions om scan workload adds.
// kms:CreateGrant and kms:Decrypt are the grant an encrypted root volume needs.
var Permissions = []string{
	"ec2:DescribeInstances",
	"ec2:CreateSnapshot",
	"ec2:DescribeSnapshots",
	"ec2:DeleteSnapshot",
	"ec2:CreateVolume",
	"ec2:DescribeVolumes",
	"ec2:AttachVolume",
	"ec2:DetachVolume",
	"ec2:DeleteVolume",
	"ec2:CreateTags",
	"kms:CreateGrant",
	"kms:Decrypt",
	"kms:DescribeKey",
	"kms:GenerateDataKeyWithoutPlaintext",
	"kms:ReEncryptFrom",
	"kms:ReEncryptTo",
}

// Worker is the EC2 instance the scan runs on.
type Worker struct {
	InstanceID       string
	AvailabilityZone string
	Region           string
}

// Result is one instance after the snapshot has been deleted.
type Result struct {
	InstanceID string
	Name       string
	Packages   []string
	Skipped    string
}

// Scanner snapshots Linux root volumes, reads them, and deletes what it created.
type Scanner struct {
	API     ec2API
	Worker  Worker
	Only    []string
	Timeout time.Duration
	Poll    time.Duration
	Mount   func(ctx context.Context, volumeID string) (root string, cleanup func() error, err error)
	Walk    func(root string) ([]string, error)
	OnStart func(instanceID, name string)

	cleanupErrs []error
}

type ec2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	CreateSnapshot(context.Context, *ec2.CreateSnapshotInput, ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	CreateVolume(context.Context, *ec2.CreateVolumeInput, ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	AttachVolume(context.Context, *ec2.AttachVolumeInput, ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(context.Context, *ec2.DetachVolumeInput, ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
	DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

var _ ec2API = (*ec2.Client)(nil)

// Scan reads each Linux root volume and calls write after that instance's
// snapshot and volume are deleted. A skip leaves packages unchanged.
func (s *Scanner) Scan(ctx context.Context, write func(Result) error) error {
	if s.Worker.InstanceID == "" || s.Worker.AvailabilityZone == "" {
		return fmt.Errorf("worker instance id and availability zone are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing an EC2 client, mount, or package walker")
	}
	targets, worker, err := s.list(ctx)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	var failed []error
	for _, inst := range targets {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		res, scanErr := s.scanInstance(ictx, inst, worker)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", res.InstanceID, err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *Scanner) list(ctx context.Context) ([]ec2types.Instance, ec2types.Instance, error) {
	instances, err := s.describe(ctx, nil)
	if err != nil {
		return nil, ec2types.Instance{}, err
	}
	byID := map[string]ec2types.Instance{}
	for _, inst := range instances {
		byID[aws.ToString(inst.InstanceId)] = inst
	}
	worker, ok := byID[s.Worker.InstanceID]
	if !ok {
		return nil, ec2types.Instance{}, fmt.Errorf("worker %s is not in this region", s.Worker.InstanceID)
	}
	if len(s.Only) == 0 {
		return instances, worker, nil
	}
	var targets []ec2types.Instance
	for _, id := range s.Only {
		inst, ok := byID[id]
		if !ok {
			return nil, ec2types.Instance{}, fmt.Errorf("instance %s is not in this region", id)
		}
		targets = append(targets, inst)
	}
	return targets, worker, nil
}

func (s *Scanner) describe(ctx context.Context, ids []string) ([]ec2types.Instance, error) {
	input := &ec2.DescribeInstancesInput{}
	if len(ids) > 0 {
		input.InstanceIds = ids
	}
	var out []ec2types.Instance
	for {
		page, err := s.API.DescribeInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, reservation := range page.Reservations {
			out = append(out, reservation.Instances...)
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		input.NextToken = page.NextToken
	}
}

func (s *Scanner) scanInstance(ctx context.Context, inst, worker ec2types.Instance) (Result, error) {
	id := aws.ToString(inst.InstanceId)
	res := Result{InstanceID: id, Name: instanceName(inst)}
	if !scannableState(inst) {
		res.Skipped = "not running"
		return res, nil
	}
	if isWindows(inst) {
		res.Skipped = "Windows"
		return res, nil
	}
	volumeID, skip, err := rootVolume(inst)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}
	if skip != "" {
		res.Skipped = skip
		return res, nil
	}

	if s.OnStart != nil {
		s.OnStart(id, res.Name)
	}
	snapID, err := s.createSnapshot(ctx, volumeID, id)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}
	defer s.deleteSnapshot(snapID)
	if err := s.waitSnapshot(ctx, snapID); err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}

	volID, err := s.createVolume(ctx, snapID, id)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}
	defer s.deleteVolume(volID)
	if err := s.waitVolume(ctx, volID, ec2types.VolumeStateAvailable); err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}

	device := freeDevice(worker.BlockDeviceMappings)
	if device == "" {
		return Result{}, fmt.Errorf("%s: no free device name on the worker", id)
	}
	_, err = s.API.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device:     aws.String(device),
		InstanceId: aws.String(s.Worker.InstanceID),
		VolumeId:   aws.String(volID),
	})
	if err != nil {
		return Result{}, fmt.Errorf("%s: attach volume: %w", id, err)
	}
	defer s.detach(volID)
	if err := s.waitAttached(ctx, volID); err != nil {
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}

	root, unmount, err := s.Mount(ctx, volID)
	if err != nil {
		if reason, ok := skipReason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}
	defer func() { s.note(unmount()) }()

	pkgs, err := s.Walk(root)
	if err != nil {
		if reason, ok := skipReason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return Result{}, fmt.Errorf("%s: %w", id, err)
	}
	res.Packages = pkgs
	return res, nil
}

func (s *Scanner) createSnapshot(ctx context.Context, volumeID, instanceID string) (string, error) {
	out, err := s.API.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    aws.String(volumeID),
		Description: aws.String("OpenSourceOM workload package inventory"),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSnapshot,
			Tags:         scanTags(instanceID),
		}},
	})
	if err != nil {
		return "", fmt.Errorf("create snapshot: %w", err)
	}
	id := aws.ToString(out.SnapshotId)
	if id == "" {
		return "", fmt.Errorf("create snapshot returned an empty snapshot id")
	}
	return id, nil
}

func (s *Scanner) createVolume(ctx context.Context, snapID, instanceID string) (string, error) {
	out, err := s.API.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(s.Worker.AvailabilityZone),
		SnapshotId:       aws.String(snapID),
		VolumeType:       ec2types.VolumeTypeGp3,
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeVolume,
			Tags:         scanTags(instanceID),
		}},
	})
	if err != nil {
		return "", fmt.Errorf("create volume: %w", err)
	}
	id := aws.ToString(out.VolumeId)
	if id == "" {
		return "", fmt.Errorf("create volume returned an empty volume id")
	}
	return id, nil
}

func scanTags(instanceID string) []ec2types.Tag {
	return []ec2types.Tag{
		{Key: aws.String("opensourceom:scan"), Value: aws.String("workload")},
		{Key: aws.String("opensourceom:instance"), Value: aws.String(instanceID)},
		{Key: aws.String("Name"), Value: aws.String("opensourceom-workload-" + instanceID)},
	}
}

func (s *Scanner) waitSnapshot(ctx context.Context, id string) error {
	return s.poll(ctx, func() (bool, error) {
		out, err := s.API.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{id}})
		if err != nil {
			return false, fmt.Errorf("describe snapshot: %w", err)
		}
		if len(out.Snapshots) == 0 {
			return false, fmt.Errorf("snapshot %s disappeared", id)
		}
		switch out.Snapshots[0].State {
		case ec2types.SnapshotStateCompleted:
			return true, nil
		case ec2types.SnapshotStateError:
			return false, fmt.Errorf("snapshot %s failed", id)
		default:
			return false, nil
		}
	})
}

func (s *Scanner) waitVolume(ctx context.Context, id string, want ec2types.VolumeState) error {
	return s.poll(ctx, func() (bool, error) {
		vol, err := s.volume(ctx, id)
		if err != nil {
			return false, err
		}
		if vol.State == ec2types.VolumeStateError {
			return false, fmt.Errorf("volume %s entered the error state", id)
		}
		return vol.State == want, nil
	})
}

func (s *Scanner) waitAttached(ctx context.Context, id string) error {
	return s.poll(ctx, func() (bool, error) {
		vol, err := s.volume(ctx, id)
		if err != nil {
			return false, err
		}
		if len(vol.Attachments) == 0 {
			return false, nil
		}
		switch vol.Attachments[0].State {
		case ec2types.VolumeAttachmentStateAttached:
			return true, nil
		case ec2types.VolumeAttachmentStateDetached:
			return false, fmt.Errorf("volume %s detached during attach", id)
		default:
			return false, nil
		}
	})
}

func (s *Scanner) volume(ctx context.Context, id string) (ec2types.Volume, error) {
	out, err := s.API.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{id}})
	if err != nil {
		return ec2types.Volume{}, fmt.Errorf("describe volume: %w", err)
	}
	if len(out.Volumes) == 0 {
		return ec2types.Volume{}, fmt.Errorf("volume %s disappeared", id)
	}
	return out.Volumes[0], nil
}

func (s *Scanner) detach(volID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := s.API.DetachVolume(ctx, &ec2.DetachVolumeInput{VolumeId: aws.String(volID)})
	if isNotFound(err) {
		return
	}
	if err != nil {
		s.note(fmt.Errorf("detach volume %s: %w", volID, err))
		return
	}
	err = s.poll(ctx, func() (bool, error) {
		vol, err := s.volume(ctx, volID)
		if isNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return vol.State == ec2types.VolumeStateAvailable, nil
	})
	if err != nil {
		s.note(fmt.Errorf("detach volume %s: %w", volID, err))
	}
}

func (s *Scanner) deleteVolume(volID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := s.poll(ctx, func() (bool, error) {
		vol, err := s.volume(ctx, volID)
		if isNotFound(err) || (err != nil && strings.Contains(err.Error(), "disappeared")) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if vol.State == ec2types.VolumeStateError {
			return true, nil
		}
		return vol.State == ec2types.VolumeStateAvailable, nil
	})
	if err != nil {
		s.note(fmt.Errorf("delete volume %s: %w", volID, err))
		return
	}
	_, err = s.API.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: aws.String(volID)})
	if isNotFound(err) {
		return
	}
	if err != nil {
		s.note(fmt.Errorf("delete volume %s: %w", volID, err))
	}
}

func (s *Scanner) deleteSnapshot(snapID string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := s.API.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{SnapshotId: aws.String(snapID)})
	if isNotFound(err) {
		return
	}
	if err != nil {
		s.note(fmt.Errorf("delete snapshot %s: %w", snapID, err))
	}
}

func (s *Scanner) note(err error) {
	if err != nil {
		s.cleanupErrs = append(s.cleanupErrs, err)
	}
}

func (s *Scanner) poll(ctx context.Context, ready func() (bool, error)) error {
	interval := s.Poll
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		ok, err := ready()
		if err != nil || ok {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func isNotFound(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "InvalidSnapshot.NotFound", "InvalidVolume.NotFound":
		return true
	default:
		return false
	}
}

func skipReason(err error) (string, bool) {
	var reason interface{ SkipReason() string }
	if err != nil && errors.As(err, &reason) {
		return reason.SkipReason(), true
	}
	return "", false
}

func rootVolume(inst ec2types.Instance) (string, string, error) {
	if inst.RootDeviceType == ec2types.DeviceTypeInstanceStore {
		return "", "instance store root", nil
	}
	if inst.RootDeviceType != ec2types.DeviceTypeEbs {
		return "", "no EBS root volume", nil
	}
	root := aws.ToString(inst.RootDeviceName)
	for _, mapping := range inst.BlockDeviceMappings {
		if aws.ToString(mapping.DeviceName) != root || mapping.Ebs == nil {
			continue
		}
		id := aws.ToString(mapping.Ebs.VolumeId)
		if id == "" {
			return "", "", fmt.Errorf("root device %s has no volume id", root)
		}
		return id, "", nil
	}
	return "", "", fmt.Errorf("root device %s is not attached", root)
}

func freeDevice(mappings []ec2types.InstanceBlockDeviceMapping) string {
	used := map[string]bool{}
	for _, mapping := range mappings {
		name := aws.ToString(mapping.DeviceName)
		used[name] = true
		used[deviceAlias(name)] = true
	}
	for letter := byte('f'); letter <= 'p'; letter++ {
		sd := "/dev/sd" + string(letter)
		if !used[sd] && !used["/dev/xvd"+string(letter)] {
			return sd
		}
	}
	return ""
}

func deviceAlias(name string) string {
	switch {
	case strings.HasPrefix(name, "/dev/xvd") && len(name) == len("/dev/xvdf"):
		return "/dev/sd" + name[len(name)-1:]
	case strings.HasPrefix(name, "/dev/sd") && len(name) == len("/dev/sdf"):
		return "/dev/xvd" + name[len(name)-1:]
	default:
		return name
	}
}

func isWindows(inst ec2types.Instance) bool {
	if inst.Platform == ec2types.PlatformValuesWindows {
		return true
	}
	return strings.Contains(strings.ToLower(aws.ToString(inst.PlatformDetails)), "windows")
}

func scannableState(inst ec2types.Instance) bool {
	if inst.State == nil {
		return false
	}
	switch inst.State.Name {
	case ec2types.InstanceStateNameRunning, ec2types.InstanceStateNameStopped:
		return true
	default:
		return false
	}
}

func instanceName(inst ec2types.Instance) string {
	for _, tag := range inst.Tags {
		if aws.ToString(tag.Key) == "Name" && tag.Value != nil {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(inst.InstanceId)
}
