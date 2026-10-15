// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// LookupWorker reads this instance's id, availability zone, and region from IMDS.
func LookupWorker(ctx context.Context) (Worker, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return Worker{}, fmt.Errorf("load aws config: %w", err)
	}
	client := imds.NewFromConfig(cfg)
	id, err := metadata(ctx, client, "instance-id")
	if err != nil {
		return Worker{}, fmt.Errorf("om scan workload runs on an EC2 instance in this account: %w", err)
	}
	az, err := metadata(ctx, client, "placement/availability-zone")
	if err != nil {
		return Worker{}, fmt.Errorf("read availability zone: %w", err)
	}
	region, err := metadata(ctx, client, "placement/region")
	if err != nil {
		return Worker{}, fmt.Errorf("read region: %w", err)
	}
	return Worker{InstanceID: id, AvailabilityZone: az, Region: region}, nil
}

func metadata(ctx context.Context, client *imds.Client, path string) (string, error) {
	out, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return "", err
	}
	defer out.Content.Close()
	body, err := io.ReadAll(out.Content)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(body))
	if value == "" {
		return "", fmt.Errorf("empty %s", path)
	}
	return value, nil
}

// CheckRegion reports when the worker's region differs from AWS_REGION.
func CheckRegion(workerRegion, configured string) error {
	if workerRegion == "" || configured == "" {
		return fmt.Errorf("AWS region is empty")
	}
	if workerRegion != configured {
		return fmt.Errorf("this instance is in %s; set AWS_REGION=%s", workerRegion, workerRegion)
	}
	return nil
}
