// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const assumeRoleSession = "opensourceom"

// NewCollectorWithRole uses the default credential chain. When roleARN is set,
// the chain assumes that role. externalID is sent only when it is not empty.
func NewCollectorWithRole(ctx context.Context, region, roleARN, externalID string) (*Collector, error) {
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := loadConfig(ctx, region, roleARN, externalID)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}
	return &Collector{
		Region:     region,
		AccountID:  aws.ToString(identity.Account),
		roleARN:    strings.TrimSpace(roleARN),
		externalID: strings.TrimSpace(externalID),
	}, nil
}

// LoadConfig uses the default credential chain. A role ARN assumes that role.
func LoadConfig(ctx context.Context, region, roleARN, externalID string) (aws.Config, error) {
	return loadConfig(ctx, region, roleARN, externalID)
}

func loadConfig(ctx context.Context, region, roleARN, externalID string) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil || strings.TrimSpace(roleARN) == "" {
		return cfg, err
	}
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), strings.TrimSpace(roleARN), assumeRoleOptions(externalID))
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.NewCredentialsCache(provider)),
	)
}

func assumeRoleOptions(externalID string) func(*stscreds.AssumeRoleOptions) {
	return func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = assumeRoleSession
		if strings.TrimSpace(externalID) != "" {
			options.ExternalID = aws.String(strings.TrimSpace(externalID))
		}
	}
}
