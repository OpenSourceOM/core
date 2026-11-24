// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
	awscol "github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// Identity is the caller a verify call reached.
type Identity struct {
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
	Principal string `json:"principal"`
	Region    string `json:"region"`
	Target    string `json:"target"`
}

// Verify checks the inventory grant, or the AWS snapshot role when target is "snapshot".
func Verify(ctx context.Context, conn graph.CloudConnection, target string) (Identity, error) {
	normalize(&conn)
	if err := Validate(conn); err != nil {
		return Identity{}, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		target = "inventory"
	}
	switch conn.Provider {
	case "aws":
		return verifyAWS(ctx, conn, target)
	case "azure":
		if target != "inventory" {
			return Identity{}, &Invalid{Message: "Azure verify checks the subscription. The snapshot grant is the production script."}
		}
		return verifyAzure(ctx, conn)
	case "gcp":
		if target != "inventory" {
			return Identity{}, &Invalid{Message: "GCP verify checks the project. The snapshot grant is the production script."}
		}
		return verifyGCP(ctx, conn)
	default:
		return Identity{}, &Invalid{Message: "Choose AWS, Azure, or GCP."}
	}
}

func verifyAWS(ctx context.Context, conn graph.CloudConnection, target string) (Identity, error) {
	roleARN := conn.InventoryRoleARN
	switch target {
	case "inventory":
	case "snapshot":
		if conn.SnapshotRoleARN == "" {
			return Identity{}, &Invalid{Message: "Paste the snapshot role ARN from the production stack."}
		}
		roleARN = conn.SnapshotRoleARN
	default:
		return Identity{}, &Invalid{Message: "Verify the inventory role or the snapshot role."}
	}
	cfg, err := awscol.LoadConfig(ctx, conn.Region, roleARN, conn.ExternalID)
	if err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("load aws config: %w", err)}
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("get caller identity: %w", err)}
	}
	if target == "inventory" {
		max := int32(1)
		if _, err := iam.NewFromConfig(cfg).ListRoles(ctx, &iam.ListRolesInput{MaxItems: &max}); err != nil {
			return Identity{}, &CloudError{Err: fmt.Errorf("iam:ListRoles: %w", err)}
		}
	}
	return Identity{
		Provider:  "aws",
		AccountID: aws.ToString(identity.Account),
		Principal: aws.ToString(identity.Arn),
		Region:    conn.Region,
		Target:    target,
	}, nil
}

func verifyAzure(ctx context.Context, conn graph.CloudConnection) (Identity, error) {
	if conn.AccountID == "" {
		return Identity{}, &Invalid{Message: "Paste the subscription id."}
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("azure credentials: %w", err)}
	}
	client, err := armresources.NewResourceGroupsClient(conn.AccountID, cred, nil)
	if err != nil {
		return Identity{}, &CloudError{Err: err}
	}
	if _, err := client.NewListPager(nil).NextPage(ctx); err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("list resource groups: %w", err)}
	}
	return Identity{
		Provider:  "azure",
		AccountID: conn.AccountID,
		Region:    conn.Location,
		Target:    "inventory",
	}, nil
}

func verifyGCP(ctx context.Context, conn graph.CloudConnection) (Identity, error) {
	if conn.AccountID == "" {
		return Identity{}, &Invalid{Message: "Paste the project id."}
	}
	service, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("resource manager: %w", err)}
	}
	project, err := service.Projects.Get(conn.AccountID).Context(ctx).Do()
	if err != nil {
		return Identity{}, &CloudError{Err: fmt.Errorf("get project: %w", err)}
	}
	id := conn.AccountID
	if project != nil && project.ProjectId != "" {
		id = project.ProjectId
	}
	return Identity{
		Provider:  "gcp",
		AccountID: id,
		Region:    conn.Region,
		Target:    "inventory",
	}, nil
}
