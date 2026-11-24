// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"fmt"

	awscol "github.com/OpenSourceOM/core/internal/collectors/aws"
	"github.com/OpenSourceOM/core/internal/collectors/azure"
	"github.com/OpenSourceOM/core/internal/collectors/gcp"
	"github.com/OpenSourceOM/core/internal/graph"
)

// Inventory runs the read-only collector for a saved connection.
func Inventory(ctx context.Context, conn graph.CloudConnection) (graph.Batch, []graph.Scope, string, error) {
	normalize(&conn)
	if err := Validate(conn); err != nil {
		return graph.Batch{}, nil, "", err
	}
	switch conn.Provider {
	case "aws":
		collector, err := awscol.NewCollectorWithRole(ctx, conn.Region, conn.InventoryRoleARN, conn.ExternalID)
		if err != nil {
			return graph.Batch{}, nil, "", &CloudError{Err: err}
		}
		batch, err := collector.Collect(ctx)
		if err != nil {
			return graph.Batch{}, nil, "", &CloudError{Err: err}
		}
		label := fmt.Sprintf("AWS account %s (%s)", collector.AccountID, conn.Region)
		return batch, []graph.Scope{{
			AccountID: collector.AccountID,
			Regions:   []string{conn.Region, ""},
		}}, label, nil
	case "azure":
		if conn.AccountID == "" {
			return graph.Batch{}, nil, "", &Invalid{Message: "Paste the subscription id."}
		}
		collector := azure.NewCollector(conn.AccountID, conn.Location)
		batch, err := collector.Collect(ctx)
		if err != nil {
			return graph.Batch{}, nil, "", &CloudError{Err: err}
		}
		label := fmt.Sprintf("Azure subscription %s", conn.AccountID)
		return batch, []graph.Scope{{AccountID: conn.AccountID}}, label, nil
	case "gcp":
		if conn.AccountID == "" {
			return graph.Batch{}, nil, "", &Invalid{Message: "Paste the project id."}
		}
		collector := gcp.NewCollector(conn.AccountID, conn.Region)
		batch, err := collector.Collect(ctx)
		if err != nil {
			return graph.Batch{}, nil, "", &CloudError{Err: err}
		}
		label := fmt.Sprintf("GCP project %s", conn.AccountID)
		return batch, []graph.Scope{{AccountID: conn.AccountID}}, label, nil
	default:
		return graph.Batch{}, nil, "", &Invalid{Message: "Choose AWS, Azure, or GCP."}
	}
}
