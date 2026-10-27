// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// ImagePermissions are the IAM actions om scan workload image adds.
// The AMI's own snapshot is not deleted. kms:CreateGrant and kms:Decrypt are
// the grant an encrypted image snapshot needs when the volume is created.
var ImagePermissions = []string{
	"ec2:DescribeInstances",
	"ec2:DescribeImages",
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

// ImageInstance is an EC2 instance launched from one boot image.
type ImageInstance struct {
	ID   string
	Name string
}

// ImageResult is one AMI after the volume created for the read is deleted.
// Instances lists every instance in the region launched from this image.
// Packages is the image walk only. A package that exists only on an instance
// disk is not included.
type ImageResult struct {
	ImageID   string
	Name      string
	Packages  []string
	Skipped   string
	Instances []ImageInstance
}

type bootImage struct {
	image  ec2types.Image
	denied bool
}

// ScanImages reads each boot image once and calls write after the volume
// created for that image is deleted. Owned images are read even when no
// instance is running. A skip leaves packages unchanged.
func (s *Scanner) ScanImages(ctx context.Context, only []string, write func(ImageResult) error) error {
	if s.Worker.InstanceID == "" || s.Worker.AvailabilityZone == "" {
		return fmt.Errorf("worker instance id and availability zone are required")
	}
	if s.API == nil || s.Mount == nil || s.Walk == nil {
		return fmt.Errorf("workload scan is missing an EC2 client, mount, or package walker")
	}
	instances, err := s.describe(ctx, nil)
	if err != nil {
		return err
	}
	var worker ec2types.Instance
	found := false
	for _, inst := range instances {
		if aws.ToString(inst.InstanceId) == s.Worker.InstanceID {
			worker = inst
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("worker %s is not in this region", s.Worker.InstanceID)
	}
	images, err := s.bootImages(ctx, instances, only)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	var failed []error
	for _, img := range images {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		res, scanErr := s.scanImage(ictx, img, instances, worker)
		cancel()
		if scanErr != nil {
			failed = append(failed, scanErr)
			continue
		}
		if write != nil {
			if err := write(res); err != nil {
				failed = append(failed, fmt.Errorf("%s: %w", res.ImageID, err))
			}
		}
	}
	return errors.Join(append(failed, s.cleanupErrs...)...)
}

func (s *Scanner) bootImages(ctx context.Context, instances []ec2types.Instance, only []string) ([]bootImage, error) {
	owned, err := s.describeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return nil, fmt.Errorf("describe images: %w", err)
	}
	byID := map[string]bootImage{}
	for _, img := range owned {
		id := aws.ToString(img.ImageId)
		if id == "" {
			continue
		}
		byID[id] = bootImage{image: img}
	}
	var missing []string
	seen := map[string]bool{}
	for _, inst := range instances {
		id := aws.ToString(inst.ImageId)
		if id == "" || seen[id] {
			continue
		}
		if _, ok := byID[id]; ok {
			continue
		}
		seen[id] = true
		missing = append(missing, id)
	}
	for _, want := range only {
		if !strings.HasPrefix(want, "ami-") || seen[want] {
			continue
		}
		if _, ok := byID[want]; ok {
			continue
		}
		seen[want] = true
		missing = append(missing, want)
	}
	for _, id := range missing {
		imgs, err := s.describeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{id}})
		if err != nil || len(imgs) == 0 {
			if err != nil && !cannotSnapshotImage(err) && !isNotFound(err) {
				return nil, fmt.Errorf("describe image %s: %w", id, err)
			}
			byID[id] = bootImage{image: ec2types.Image{ImageId: aws.String(id)}, denied: true}
			continue
		}
		got := aws.ToString(imgs[0].ImageId)
		if got == "" {
			got = id
		}
		byID[got] = bootImage{image: imgs[0]}
	}

	var images []bootImage
	for _, img := range byID {
		images = append(images, img)
	}
	slices.SortFunc(images, func(a, b bootImage) int {
		return strings.Compare(aws.ToString(a.image.ImageId), aws.ToString(b.image.ImageId))
	})
	return selectBootImages(images, only)
}

func selectBootImages(images []bootImage, only []string) ([]bootImage, error) {
	if len(only) == 0 {
		return images, nil
	}
	var out []bootImage
	for _, want := range only {
		var matched []bootImage
		for _, img := range images {
			if aws.ToString(img.image.ImageId) == want || aws.ToString(img.image.Name) == want {
				matched = append(matched, img)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("image %s is not in this region", want)
		}
		if len(matched) > 1 {
			return nil, fmt.Errorf("image %s matches more than one image; pass the image id", want)
		}
		out = append(out, matched[0])
	}
	return out, nil
}

func (s *Scanner) describeImages(ctx context.Context, input *ec2.DescribeImagesInput) ([]ec2types.Image, error) {
	var out []ec2types.Image
	for {
		page, err := s.API.DescribeImages(ctx, input)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Images...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		input.NextToken = page.NextToken
	}
}

func (s *Scanner) scanImage(ctx context.Context, item bootImage, instances []ec2types.Instance, worker ec2types.Instance) (ImageResult, error) {
	img := item.image
	id := aws.ToString(img.ImageId)
	res := ImageResult{ImageID: id, Name: aws.ToString(img.Name), Instances: instancesUsing(id, instances)}
	if item.denied {
		res.Skipped = workload.ErrImageDenied.Error()
		return res, nil
	}
	if imageWindows(img) {
		res.Skipped = "Windows"
		return res, nil
	}
	if img.State != "" && img.State != ec2types.ImageStateAvailable {
		res.Skipped = "not available"
		return res, nil
	}
	snapID, skip := imageRootSnapshot(img)
	if skip != "" {
		res.Skipped = skip
		return res, nil
	}
	if s.OnStart != nil {
		s.OnStart(id, res.Name)
	}

	volID, err := s.createImageVolume(ctx, snapID, id)
	if volID != "" {
		defer s.deleteVolume(volID)
	}
	if err != nil {
		if cannotSnapshotImage(err) {
			res.Skipped = workload.ErrImageDenied.Error()
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", id, err)
	}
	if err := s.waitVolume(ctx, volID, ec2types.VolumeStateAvailable); err != nil {
		return ImageResult{}, fmt.Errorf("%s: %w", id, err)
	}
	device := freeDevice(worker.BlockDeviceMappings)
	if device == "" {
		return ImageResult{}, fmt.Errorf("%s: no free device name on the worker", id)
	}
	_, err = s.API.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device:     aws.String(device),
		InstanceId: aws.String(s.Worker.InstanceID),
		VolumeId:   aws.String(volID),
	})
	if err != nil {
		return ImageResult{}, fmt.Errorf("%s: attach volume: %w", id, err)
	}
	defer s.detach(volID)
	if err := s.waitAttached(ctx, volID); err != nil {
		return ImageResult{}, fmt.Errorf("%s: %w", id, err)
	}

	root, unmount, err := s.Mount(ctx, volID)
	if err != nil {
		if reason, ok := skipReason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", id, err)
	}
	defer func() { s.note(unmount()) }()

	pkgs, err := s.Walk(root)
	if err != nil {
		if reason, ok := skipReason(err); ok {
			res.Skipped = reason
			return res, nil
		}
		return ImageResult{}, fmt.Errorf("%s: %w", id, err)
	}
	res.Packages = pkgs
	return res, nil
}

func (s *Scanner) createImageVolume(ctx context.Context, snapID, imageID string) (string, error) {
	out, err := s.API.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(s.Worker.AvailabilityZone),
		SnapshotId:       aws.String(snapID),
		VolumeType:       ec2types.VolumeTypeGp3,
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeVolume,
			Tags:         imageVolumeTags(imageID),
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

func imageVolumeTags(imageID string) []ec2types.Tag {
	return []ec2types.Tag{
		{Key: aws.String("opensourceom:scan"), Value: aws.String("workload")},
		{Key: aws.String("opensourceom:image"), Value: aws.String(imageID)},
		{Key: aws.String("Name"), Value: aws.String("opensourceom-workload-" + imageID)},
	}
}

func instancesUsing(imageID string, instances []ec2types.Instance) []ImageInstance {
	var out []ImageInstance
	for _, inst := range instances {
		if aws.ToString(inst.ImageId) != imageID {
			continue
		}
		out = append(out, ImageInstance{ID: aws.ToString(inst.InstanceId), Name: instanceName(inst)})
	}
	slices.SortFunc(out, func(a, b ImageInstance) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func imageRootSnapshot(img ec2types.Image) (string, string) {
	if img.RootDeviceType == ec2types.DeviceTypeInstanceStore {
		return "", "instance store root"
	}
	if img.RootDeviceType != "" && img.RootDeviceType != ec2types.DeviceTypeEbs {
		return "", "no EBS root snapshot"
	}
	root := aws.ToString(img.RootDeviceName)
	if root == "" {
		return "", "no EBS root snapshot"
	}
	for _, mapping := range img.BlockDeviceMappings {
		if aws.ToString(mapping.DeviceName) != root {
			continue
		}
		if mapping.Ebs == nil {
			return "", "no EBS root snapshot"
		}
		id := aws.ToString(mapping.Ebs.SnapshotId)
		if id == "" {
			return "", "no EBS root snapshot"
		}
		return id, ""
	}
	return "", "no EBS root snapshot"
}

func imageWindows(img ec2types.Image) bool {
	if img.Platform == ec2types.PlatformValuesWindows {
		return true
	}
	return strings.Contains(strings.ToLower(aws.ToString(img.PlatformDetails)), "windows")
}

func cannotSnapshotImage(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "UnauthorizedOperation", "OperationNotPermitted", "OptInRequired", "AuthFailure", "InvalidSnapshot.NotFound", "InvalidAMIID.NotFound":
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, code := range []string{
		"unauthorizedoperation",
		"operationnotpermitted",
		"optinrequired",
		"authfailure",
		"invalidsnapshot.notfound",
		"invalidamiid.notfound",
	} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}
