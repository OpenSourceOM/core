// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	azurev "github.com/OpenSourceOM/core/internal/workload/azure"
	gcpv "github.com/OpenSourceOM/core/internal/workload/gcp"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultAzureSnapshotGroup = "opensourceom-snapshots"

var (
	awsSnapshotRole    string
	awsExternalID      string
	awsKMSKey          string
	azureSnapshotGroup string
)

func granted(title string, actions []string) string {
	return title + ":\n  " + strings.Join(actions, "\n  ")
}

func loadScannerAWS(ctx context.Context, region string) (localCfg, prodCfg aws.Config, scannerAccount, prodAccount string, err error) {
	role := firstText(awsSnapshotRole, os.Getenv("OM_SNAPSHOT_ROLE_ARN"))
	external := firstText(awsExternalID, os.Getenv("OM_EXTERNAL_ID"))
	if role == "" || external == "" {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("set --snapshot-role and --external-id to the production role from deploy/connect/aws")
	}
	localCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("load aws config: %w", err)
	}
	localSTS := sts.NewFromConfig(localCfg)
	ident, err := localSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("scanner account: %w", err)
	}
	scannerAccount = aws.ToString(ident.Account)
	provider := stscreds.NewAssumeRoleProvider(localSTS, role, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(external)
		o.RoleSessionName = "opensourceom-workload"
	})
	prodCfg = localCfg.Copy()
	prodCfg.Credentials = aws.NewCredentialsCache(provider)
	prodIdent, err := sts.NewFromConfig(prodCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("assume %s: %w", role, err)
	}
	prodAccount = aws.ToString(prodIdent.Account)
	if prodAccount == "" || scannerAccount == "" {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("aws account id is empty")
	}
	if prodAccount == scannerAccount {
		return aws.Config{}, aws.Config{}, "", "", fmt.Errorf("snapshot role %s is in the scanner account; create it in the production account", role)
	}
	return localCfg, prodCfg, scannerAccount, prodAccount, nil
}

func scannerKMSKey() string {
	return firstText(awsKMSKey, os.Getenv("OM_SCANNER_KMS_KEY_ID"))
}

func azureClients(prodSub, workerSub string) (prod, scanner *azurev.Client, group string, err error) {
	prod, err = azurev.NewClient(prodSub)
	if err != nil {
		return nil, nil, "", err
	}
	if strings.EqualFold(workerSub, prodSub) {
		return prod, nil, "", nil
	}
	scanner, err = azurev.NewClient(workerSub)
	if err != nil {
		return nil, nil, "", err
	}
	group = firstText(azureSnapshotGroup, defaultAzureSnapshotGroup)
	return prod, scanner, group, nil
}

func gcpClients(ctx context.Context, prodProject, workerProject string) (prod, scanner *gcpv.Client, err error) {
	prod, err = gcpv.NewClient(ctx, prodProject)
	if err != nil {
		return nil, nil, err
	}
	if workerProject == prodProject {
		return prod, nil, nil
	}
	scanner, err = gcpv.NewClient(ctx, workerProject)
	if err != nil {
		return nil, nil, err
	}
	return prod, scanner, nil
}

func firstText(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
