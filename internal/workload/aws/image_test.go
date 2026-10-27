// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/OpenSourceOM/core/internal/workload"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

func TestImagePermissionsDoNotDeleteTheImageSnapshot(t *testing.T) {
	if !slices.Contains(ImagePermissions, "ec2:DescribeImages") || !slices.Contains(ImagePermissions, "ec2:CreateVolume") {
		t.Fatalf("permissions = %v", ImagePermissions)
	}
	for _, action := range []string{"ec2:CreateSnapshot", "ec2:DeleteSnapshot"} {
		if slices.Contains(ImagePermissions, action) {
			t.Errorf("image scan must not %s", action)
		}
	}
}

func TestScanImageOnceAppliesTheSamePackages(t *testing.T) {
	fake := newFake(imageInstances())
	fake.images = []ec2types.Image{testAMI("ami-golden", "golden", "snap-golden"), testAMI("ami-worker", "worker", "snap-worker")}
	var mounts int
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		mounts++
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error { return nil }, nil
	}, workload.Walk)

	var got []ImageResult
	err := scanner.ScanImages(context.Background(), []string{"ami-golden"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if mounts != 1 || len(got) != 1 || got[0].Skipped != "" {
		t.Fatalf("mounts=%d results=%#v", mounts, got)
	}
	if len(got[0].Instances) != 2 || got[0].Instances[0].ID != "i-api" || got[0].Instances[1].ID != "i-web" {
		t.Fatalf("instances = %#v", got[0].Instances)
	}
	joined := strings.Join(got[0].Packages, "\n")
	if !strings.Contains(joined, "pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1") || strings.Contains(joined, "nginx") {
		t.Fatalf("packages =\n%s", joined)
	}
	if slices.Contains(fake.log, "CreateSnapshot") || slices.Contains(fake.log, "DeleteSnapshot") {
		t.Fatalf("image snapshot was created or deleted: %v", fake.log)
	}
	if len(fake.volInputs) != 1 || aws.ToString(fake.volInputs[0].SnapshotId) != "snap-golden" {
		t.Fatalf("volumes = %#v", fake.volInputs)
	}
	if tagValue(fake.volInputs[0].TagSpecifications[0].Tags, "opensourceom:image") != "ami-golden" {
		t.Fatalf("tags = %#v", fake.volInputs[0].TagSpecifications)
	}
	if len(fake.vols) != 0 {
		t.Fatal("volume left behind")
	}
}

func TestScanImageReadsAnOwnedImageWithNoInstances(t *testing.T) {
	fake := newFake(imageInstances())
	fake.images = []ec2types.Image{testAMI("ami-idle", "idle", "snap-idle"), testAMI("ami-worker", "worker", "snap-worker")}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error { return nil }, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.ScanImages(context.Background(), []string{"ami-idle"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Instances) != 0 || got[0].Skipped != "" || len(got[0].Packages) == 0 {
		t.Fatalf("results = %#v", got)
	}
	if len(fake.volInputs) != 1 || aws.ToString(fake.volInputs[0].SnapshotId) != "snap-idle" {
		t.Fatalf("volumes = %#v", fake.volInputs)
	}
}

func TestScanImageReadsASharedImageOnce(t *testing.T) {
	instances := imageInstances()
	sharedInst := linuxInstance("i-shared", "shared", "vol-shared")
	sharedInst.ImageId = aws.String("ami-shared")
	fake := newFake(append(instances, sharedInst))
	fake.images = []ec2types.Image{testAMI("ami-worker", "worker", "snap-worker")}
	fake.shared = []ec2types.Image{testAMI("ami-shared", "shared", "snap-shared")}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error { return nil }, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.ScanImages(context.Background(), []string{"ami-shared"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Instances) != 1 || got[0].Instances[0].ID != "i-shared" {
		t.Fatalf("results = %#v", got)
	}
	if len(fake.volInputs) != 1 || aws.ToString(fake.volInputs[0].SnapshotId) != "snap-shared" {
		t.Fatalf("volumes = %#v", fake.volInputs)
	}
}

func TestScanImageReportsMarketplaceItCannotSnapshot(t *testing.T) {
	instances := imageInstances()
	market := linuxInstance("i-market", "market", "vol-market")
	market.ImageId = aws.String("ami-market")
	fake := newFake(append(instances, market))
	fake.images = []ec2types.Image{testAMI("ami-worker", "worker", "snap-worker")}
	fake.shared = []ec2types.Image{testAMI("ami-market", "market", "snap-market")}
	fake.denySnap = map[string]error{"snap-market": apiErr{code: "UnauthorizedOperation"}}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("marketplace image was mounted")
		return "", nil, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.ScanImages(context.Background(), []string{"ami-market"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != workload.ErrImageDenied.Error() {
		t.Fatalf("results = %#v", got)
	}
	if len(fake.vols) != 0 || slices.Contains(fake.log, "DeleteSnapshot") {
		t.Fatalf("log=%v vols=%d", fake.log, len(fake.vols))
	}
}

func TestScanImageReportsAnImageItCannotDescribe(t *testing.T) {
	instances := imageInstances()
	hidden := linuxInstance("i-hidden", "hidden", "vol-hidden")
	hidden.ImageId = aws.String("ami-hidden")
	fake := newFake(append(instances, hidden))
	fake.images = []ec2types.Image{testAMI("ami-worker", "worker", "snap-worker")}
	fake.imageErr = map[string]error{"ami-hidden": apiErr{code: "InvalidAMIID.NotFound"}}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("hidden image was mounted")
		return "", nil, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.ScanImages(context.Background(), []string{"ami-hidden"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != workload.ErrImageDenied.Error() || len(got[0].Instances) != 1 {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "CreateVolume") {
		t.Fatal("volume created for an image the account cannot describe")
	}
}

func TestScanImageSkipsWindowsAndInstanceStore(t *testing.T) {
	fake := newFake(imageInstances())
	windows := testAMI("ami-win", "win", "snap-win")
	windows.Platform = ec2types.PlatformValuesWindows
	store := testAMI("ami-store", "store", "")
	store.RootDeviceType = ec2types.DeviceTypeInstanceStore
	store.BlockDeviceMappings = nil
	fake.images = []ec2types.Image{windows, store, testAMI("ami-worker", "worker", "snap-worker")}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("skipped image was mounted")
		return "", nil, nil
	}, workload.Walk)
	var got []ImageResult
	if err := scanner.ScanImages(context.Background(), []string{"ami-win", "ami-store"}, func(res ImageResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Skipped != "Windows" || got[1].Skipped != "instance store root" {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "CreateVolume") {
		t.Fatal("volume created for a skipped image")
	}
}

func TestScanImageDeletesVolumeWhenWalkFails(t *testing.T) {
	fake := newFake(imageInstances())
	fake.images = []ec2types.Image{testAMI("ami-golden", "golden", "snap-golden"), testAMI("ami-worker", "worker", "snap-worker")}
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return t.TempDir(), func() error { return nil }, nil
	}, func(string) ([]string, error) {
		return nil, errString("read rpm database: corrupt")
	})
	err := scanner.ScanImages(context.Background(), []string{"ami-golden"}, nil)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v", err)
	}
	assertOrder(t, fake.log, "CreateVolume", "AttachVolume", "DetachVolume", "DeleteVolume")
	if slices.Contains(fake.log, "DeleteSnapshot") || len(fake.vols) != 0 {
		t.Fatalf("log=%v vols=%d", fake.log, len(fake.vols))
	}
}

func imageInstances() []ec2types.Instance {
	worker := linuxInstance("i-worker", "worker", "vol-worker")
	worker.ImageId = aws.String("ami-worker")
	worker.BlockDeviceMappings = append(worker.BlockDeviceMappings, ec2types.InstanceBlockDeviceMapping{
		DeviceName: aws.String("/dev/sdf"),
		Ebs:        &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String("vol-extra")},
	})
	web := linuxInstance("i-web", "web", "vol-web")
	web.ImageId = aws.String("ami-golden")
	api := linuxInstance("i-api", "api", "vol-api")
	api.ImageId = aws.String("ami-golden")
	return []ec2types.Instance{worker, web, api}
}

func testAMI(id, name, snap string) ec2types.Image {
	img := ec2types.Image{
		ImageId:        aws.String(id),
		Name:           aws.String(name),
		State:          ec2types.ImageStateAvailable,
		RootDeviceType: ec2types.DeviceTypeEbs,
		RootDeviceName: aws.String("/dev/xvda"),
	}
	if snap != "" {
		img.BlockDeviceMappings = []ec2types.BlockDeviceMapping{{
			DeviceName: aws.String("/dev/xvda"),
			Ebs:        &ec2types.EbsBlockDevice{SnapshotId: aws.String(snap)},
		}}
	}
	return img
}

type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type errString string

func (e errString) Error() string { return string(e) }
