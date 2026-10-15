// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/workload"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestPermissionsCoverSnapshotLifecycle(t *testing.T) {
	for _, action := range []string{
		"ec2:CreateSnapshot",
		"ec2:AttachVolume",
		"ec2:DeleteSnapshot",
		"ec2:DeleteVolume",
		"kms:CreateGrant",
		"kms:Decrypt",
	} {
		if !slices.Contains(Permissions, action) {
			t.Errorf("missing %s", action)
		}
	}
}

func TestScanWritesPackagesAndDeletesSnapshot(t *testing.T) {
	fake := newFake(testInstances())
	var unmounted bool
	var got []Result
	scanner := testScanner(t, fake, func(ctx context.Context, volumeID string) (string, func() error, error) {
		if !strings.HasPrefix(volumeID, "vol-scan-") {
			t.Fatalf("mounted %s", volumeID)
		}
		dir := t.TempDir()
		writeRoot(t, dir)
		return dir, func() error {
			unmounted = true
			return nil
		}, nil
	}, workload.Walk)
	scanner.Only = []string{"i-web"}

	err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !unmounted {
		t.Fatal("mount was left in place")
	}
	if len(got) != 1 || got[0].Skipped != "" {
		t.Fatalf("results = %#v", got)
	}
	if got[0].Name != "web" {
		t.Fatalf("name = %s", got[0].Name)
	}
	joined := strings.Join(got[0].Packages, "\n")
	if !strings.Contains(joined, "pkg:deb/ubuntu/openssl@1.1.1n-0ubuntu1") {
		t.Fatalf("packages =\n%s", joined)
	}
	if strings.Contains(joined, "PRIVATE KEY") || strings.Contains(joined, "AKIA") {
		t.Fatalf("file contents leaked:\n%s", joined)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "AttachVolume", "DetachVolume", "DeleteVolume", "DeleteSnapshot")
	if len(fake.snapInputs) != 1 || aws.ToString(fake.snapInputs[0].VolumeId) != "vol-root" {
		t.Fatalf("snapshots = %#v", fake.snapInputs)
	}
	if len(fake.volInputs) != 1 {
		t.Fatal("expected one volume")
	}
	vol := fake.volInputs[0]
	if aws.ToString(vol.AvailabilityZone) != "us-east-1a" || aws.ToString(vol.SnapshotId) != "snap-1" {
		t.Fatalf("volume = %#v", vol)
	}
	if vol.KmsKeyId != nil || vol.Encrypted != nil || vol.VolumeType != ec2types.VolumeTypeGp3 {
		t.Fatalf("volume encryption or type = %#v", vol)
	}
	if tagValue(vol.TagSpecifications[0].Tags, "opensourceom:scan") != "workload" {
		t.Fatalf("tags = %#v", vol.TagSpecifications)
	}
	if len(fake.attachInputs) != 1 || aws.ToString(fake.attachInputs[0].Device) != "/dev/sdg" {
		t.Fatalf("attach = %#v", fake.attachInputs)
	}
	if len(fake.vols) != 0 || len(fake.snaps) != 0 {
		t.Fatalf("leftover snaps=%d vols=%d", len(fake.snaps), len(fake.vols))
	}
}

func TestScanSkipsWindowsAndInstanceStore(t *testing.T) {
	fake := newFake(append(testInstances(),
		windowsInstance("i-win"),
		storeInstance("i-store"),
	))
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("skipped instance was mounted")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"i-win", "i-store"}
	var got []Result
	err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Skipped != "Windows" || got[1].Skipped != "instance store root" {
		t.Fatalf("results = %#v", got)
	}
	if slices.Contains(fake.log, "CreateSnapshot") {
		t.Fatalf("snapshot created: %v", fake.log)
	}
}

func TestScanDeletesSnapshotWhenWalkFails(t *testing.T) {
	fake := newFake(testInstances())
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return t.TempDir(), func() error { return nil }, nil
	}, func(string) ([]string, error) {
		return nil, errors.New("read rpm database: corrupt")
	})
	scanner.Only = []string{"i-web"}
	err := scanner.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v", err)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "AttachVolume", "DetachVolume", "DeleteVolume", "DeleteSnapshot")
	if len(fake.snaps) != 0 || len(fake.vols) != 0 {
		t.Fatal("snapshot or volume was left behind")
	}
}

func TestScanSkipsLVMAfterCleanup(t *testing.T) {
	fake := newFake(testInstances())
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return "", nil, workload.ErrLVM
	}, func(string) ([]string, error) {
		t.Fatal("LVM root was walked")
		return nil, nil
	})
	scanner.Only = []string{"i-web"}
	var got []Result
	if err := scanner.Scan(context.Background(), func(res Result) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skipped != workload.ErrLVM.Error() {
		t.Fatalf("results = %#v", got)
	}
	assertOrder(t, fake.log, "CreateSnapshot", "DeleteSnapshot")
	if len(fake.snaps) != 0 {
		t.Fatal("snapshot left behind")
	}
}

func TestScanWaitsForSnapshotThenDeletesOnTimeout(t *testing.T) {
	fake := newFake(testInstances())
	fake.stuckSnapshot = true
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		t.Fatal("mounted a pending snapshot")
		return "", nil, nil
	}, workload.Walk)
	scanner.Only = []string{"i-web"}
	scanner.Timeout = 40 * time.Millisecond
	scanner.Poll = 5 * time.Millisecond
	err := scanner.Scan(context.Background(), nil)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if !slices.Contains(fake.log, "DeleteSnapshot") {
		t.Fatalf("log = %v", fake.log)
	}
	if slices.Contains(fake.log, "CreateVolume") {
		t.Fatal("volume created from a pending snapshot")
	}
}

func TestScanPaginatesInstances(t *testing.T) {
	fake := newFake(testInstances())
	fake.pages = 2
	scanner := testScanner(t, fake, func(context.Context, string) (string, func() error, error) {
		return "", nil, workload.ErrNoPackages
	}, workload.Walk)
	var ids []string
	if err := scanner.Scan(context.Background(), func(res Result) error {
		ids = append(ids, res.InstanceID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []string{"i-worker", "i-web"}) {
		t.Fatalf("ids = %v", ids)
	}
	if fake.describePages < 2 {
		t.Fatalf("describe pages = %d", fake.describePages)
	}
}

func TestFreeDeviceSkipsNamesInUse(t *testing.T) {
	got := freeDevice([]ec2types.InstanceBlockDeviceMapping{
		{DeviceName: aws.String("/dev/xvdf")},
		{DeviceName: aws.String("/dev/sdg")},
	})
	if got != "/dev/sdh" {
		t.Fatalf("device = %s", got)
	}
}

func testScanner(t *testing.T, fake *fakeEC2, mount func(context.Context, string) (string, func() error, error), walk func(string) ([]string, error)) *Scanner {
	t.Helper()
	return &Scanner{
		API: fake,
		Worker: Worker{
			InstanceID:       "i-worker",
			AvailabilityZone: "us-east-1a",
		},
		Poll:  time.Millisecond,
		Mount: mount,
		Walk:  walk,
	}
}

func testInstances() []ec2types.Instance {
	worker := linuxInstance("i-worker", "worker", "vol-worker")
	worker.BlockDeviceMappings = append(worker.BlockDeviceMappings, ec2types.InstanceBlockDeviceMapping{
		DeviceName: aws.String("/dev/sdf"),
		Ebs:        &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String("vol-extra")},
	})
	return []ec2types.Instance{
		worker,
		linuxInstance("i-web", "web", "vol-root"),
	}
}

func linuxInstance(id, name, rootVol string) ec2types.Instance {
	return ec2types.Instance{
		InstanceId:      aws.String(id),
		State:           &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		RootDeviceType:  ec2types.DeviceTypeEbs,
		RootDeviceName:  aws.String("/dev/xvda"),
		PlatformDetails: aws.String("Linux/UNIX"),
		Tags:            []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String(name)}},
		BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
			{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String(rootVol)}},
			{DeviceName: aws.String("/dev/xvdb"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String("vol-data")}},
		},
	}
}

func windowsInstance(id string) ec2types.Instance {
	inst := linuxInstance(id, "win", "vol-win")
	inst.Platform = ec2types.PlatformValuesWindows
	inst.PlatformDetails = aws.String("Windows")
	return inst
}

func storeInstance(id string) ec2types.Instance {
	inst := linuxInstance(id, "store", "")
	inst.RootDeviceType = ec2types.DeviceTypeInstanceStore
	inst.BlockDeviceMappings = nil
	return inst
}

func writeRoot(t *testing.T, root string) {
	t.Helper()
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.1.1n-0ubuntu1\nDescription: library\n BEGIN PRIVATE KEY\n"
	for _, rel := range []string{"etc/os-release", "var/lib/dpkg/status", "home/app/notes.txt"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "home/app/notes.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertOrder(t *testing.T, log []string, steps ...string) {
	t.Helper()
	at := -1
	for _, step := range steps {
		next := slices.Index(log[at+1:], step)
		if next < 0 {
			t.Fatalf("log %v missing %s after position %d", log, step, at)
		}
		at += next + 1
	}
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

type snapState struct {
	state ec2types.SnapshotState
	seen  int
}

type volRec struct {
	attached bool
}

type fakeEC2 struct {
	instances     []ec2types.Instance
	pages         int
	describePages int
	log           []string
	snapN         int
	volN          int
	snaps         map[string]*snapState
	vols          map[string]*volRec
	snapInputs    []*ec2.CreateSnapshotInput
	volInputs     []*ec2.CreateVolumeInput
	attachInputs  []*ec2.AttachVolumeInput
	stuckSnapshot bool
	delaySnapshot bool
}

func newFake(instances []ec2types.Instance) *fakeEC2 {
	return &fakeEC2{
		instances: instances,
		snaps:     map[string]*snapState{},
		vols:      map[string]*volRec{},
	}
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.log = append(f.log, "DescribeInstances")
	f.describePages++
	instances := f.instances
	var next *string
	if f.pages == 2 {
		mid := (len(instances) + 1) / 2
		if in.NextToken == nil || aws.ToString(in.NextToken) == "" {
			instances = instances[:mid]
			token := "2"
			next = &token
		} else {
			instances = instances[mid:]
		}
	}
	return &ec2.DescribeInstancesOutput{
		NextToken:    next,
		Reservations: []ec2types.Reservation{{Instances: instances}},
	}, nil
}

func (f *fakeEC2) CreateSnapshot(_ context.Context, in *ec2.CreateSnapshotInput, _ ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	f.log = append(f.log, "CreateSnapshot")
	f.snapInputs = append(f.snapInputs, in)
	f.snapN++
	id := fmt.Sprintf("snap-%d", f.snapN)
	state := ec2types.SnapshotStateCompleted
	if f.stuckSnapshot || f.delaySnapshot {
		state = ec2types.SnapshotStatePending
	}
	f.snaps[id] = &snapState{state: state}
	return &ec2.CreateSnapshotOutput{SnapshotId: aws.String(id)}, nil
}

func (f *fakeEC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	f.log = append(f.log, "DescribeSnapshots")
	if len(in.SnapshotIds) == 0 {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	st := f.snaps[in.SnapshotIds[0]]
	if st == nil {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	if f.delaySnapshot && st.state == ec2types.SnapshotStatePending {
		st.seen++
		if st.seen > 1 {
			st.state = ec2types.SnapshotStateCompleted
		}
	}
	return &ec2.DescribeSnapshotsOutput{
		Snapshots: []ec2types.Snapshot{{
			SnapshotId: aws.String(in.SnapshotIds[0]),
			State:      st.state,
		}},
	}, nil
}

func (f *fakeEC2) CreateVolume(_ context.Context, in *ec2.CreateVolumeInput, _ ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error) {
	f.log = append(f.log, "CreateVolume")
	f.volInputs = append(f.volInputs, in)
	f.volN++
	id := fmt.Sprintf("vol-scan-%d", f.volN)
	f.vols[id] = &volRec{}
	return &ec2.CreateVolumeOutput{VolumeId: aws.String(id)}, nil
}

func (f *fakeEC2) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	f.log = append(f.log, "DescribeVolumes")
	if len(in.VolumeIds) == 0 {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	id := in.VolumeIds[0]
	rec := f.vols[id]
	if rec == nil {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	vol := ec2types.Volume{VolumeId: aws.String(id), State: ec2types.VolumeStateAvailable}
	if rec.attached {
		vol.State = ec2types.VolumeStateInUse
		vol.Attachments = []ec2types.VolumeAttachment{{
			VolumeId: aws.String(id),
			State:    ec2types.VolumeAttachmentStateAttached,
		}}
	}
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{vol}}, nil
}

func (f *fakeEC2) AttachVolume(_ context.Context, in *ec2.AttachVolumeInput, _ ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error) {
	f.log = append(f.log, "AttachVolume")
	f.attachInputs = append(f.attachInputs, in)
	rec := f.vols[aws.ToString(in.VolumeId)]
	if rec == nil {
		return nil, errors.New("missing volume")
	}
	rec.attached = true
	return &ec2.AttachVolumeOutput{}, nil
}

func (f *fakeEC2) DetachVolume(_ context.Context, in *ec2.DetachVolumeInput, _ ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	f.log = append(f.log, "DetachVolume")
	rec := f.vols[aws.ToString(in.VolumeId)]
	if rec == nil {
		return nil, errors.New("missing volume")
	}
	rec.attached = false
	return &ec2.DetachVolumeOutput{}, nil
}

func (f *fakeEC2) DeleteVolume(_ context.Context, in *ec2.DeleteVolumeInput, _ ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	f.log = append(f.log, "DeleteVolume")
	id := aws.ToString(in.VolumeId)
	rec := f.vols[id]
	if rec == nil {
		return &ec2.DeleteVolumeOutput{}, nil
	}
	if rec.attached {
		return nil, errors.New("volume in use")
	}
	delete(f.vols, id)
	return &ec2.DeleteVolumeOutput{}, nil
}

func (f *fakeEC2) DeleteSnapshot(_ context.Context, in *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	f.log = append(f.log, "DeleteSnapshot")
	delete(f.snaps, aws.ToString(in.SnapshotId))
	return &ec2.DeleteSnapshotOutput{}, nil
}
