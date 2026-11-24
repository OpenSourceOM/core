// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"fmt"
	"net/url"
	"strings"

	assets "github.com/OpenSourceOM/core/deploy/connect"
	"github.com/OpenSourceOM/core/internal/graph"
)

// TemplateBaseURL is where AWS fetches CloudFormation templates. Download from
// the API when that URL is not reachable.
const TemplateBaseURL = "https://raw.githubusercontent.com/OpenSourceOM/core/main/deploy/connect/"

// Link is one grant the connect screen can open or copy.
type Link struct {
	Label    string `json:"label"`
	URL      string `json:"url,omitempty"`
	Template string `json:"template,omitempty"`
	Script   string `json:"script,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Setup is a saved connection plus the grants and the one command left for the worker.
type Setup struct {
	Connection      graph.CloudConnection `json:"connection"`
	Steps           []string              `json:"steps"`
	Links           []Link                `json:"links"`
	WorkloadCommand string                `json:"workload_command"`
}

// Present fills deploy links from the saved connection.
func Present(conn graph.CloudConnection) (Setup, error) {
	normalize(&conn)
	setup := Setup{Connection: conn, Steps: steps(conn.Provider)}
	var err error
	switch conn.Provider {
	case "aws":
		setup.Links, err = awsLinks(conn)
		setup.WorkloadCommand = awsWorkloadCommand(conn)
	case "azure":
		setup.Links, err = scriptLinks([]scriptLink{
			{"Inventory grant", "azure-inventory", "Run this in the subscription you want to read. Set AZURE_PRINCIPAL_TYPE=User when the principal is a person.", map[string]string{
				"AZURE_SUBSCRIPTION_ID": conn.AccountID,
				"AZURE_PRINCIPAL_ID":    conn.InventoryPrincipal,
			}},
			{"Scanner grant", "azure-scanner", "Run this in the subscription where the worker lives.", map[string]string{
				"AZURE_SUBSCRIPTION_ID": first(conn.ScannerAccountID, conn.AccountID),
				"AZURE_LOCATION":        conn.Location,
				"AZURE_RESOURCE_GROUP":  conn.ResourceGroup,
			}},
			{"Production grant", "azure-production", "Run this in the subscription you want to read, after the scanner identity exists.", map[string]string{
				"AZURE_SUBSCRIPTION_ID": conn.AccountID,
				"AZURE_LOCATION":        conn.Location,
				"SCANNER_PRINCIPAL_ID":  conn.ScannerPrincipal,
			}},
		})
		setup.WorkloadCommand = "sudo -E om scan workload azure"
	case "gcp":
		account := strings.TrimPrefix(conn.ScannerPrincipal, "serviceAccount:")
		setup.Links, err = scriptLinks([]scriptLink{
			{"Inventory grant", "gcp-inventory", "Run this in the project you want to read. GCP_MEMBER is user:you@example.com or a service account.", map[string]string{
				"GCP_PROJECT_ID": conn.AccountID,
				"GCP_MEMBER":     conn.InventoryPrincipal,
			}},
			{"Scanner grant", "gcp-scanner", "Run this in the project where the worker lives.", map[string]string{
				"GCP_PROJECT_ID": first(conn.ScannerAccountID, conn.AccountID),
			}},
			{"Production grant", "gcp-production", "Run this in the project you want to read.", map[string]string{
				"GCP_PROJECT_ID":          conn.AccountID,
				"SCANNER_SERVICE_ACCOUNT": account,
			}},
		})
		setup.WorkloadCommand = "sudo -E om scan workload gcp"
	default:
		return Setup{}, &Invalid{Message: "Choose AWS, Azure, or GCP."}
	}
	if err != nil {
		return Setup{}, err
	}
	return setup, nil
}

func steps(provider string) []string {
	switch provider {
	case "aws":
		return []string{
			"Copy the external id. The stacks require it. It is not an access key.",
			"Open the inventory stack in the account you want to read and approve it. Leave the principal empty to trust that account, or paste the role that runs OpenSourceOM.",
			"Paste the inventory role ARN from the stack output. Leave it empty when this server already has read access. Check the region, verify, then run the inventory scan.",
			"For packages on disks, open the scanner stack in the account where the worker runs, then the production stack in the account you read. Paste both role ARNs.",
			"On the worker, as root, run the command at the bottom. The browser does not start that scan.",
		}
	case "azure":
		return []string{
			"This server uses its Azure login or a managed identity. The form does not take a client secret.",
			"Copy the inventory script and run it in Cloud Shell. It assigns Reader and Monitoring Reader.",
			"Paste the subscription id, verify, then run the inventory scan.",
			"For packages on disks, run the scanner script in the subscription where the worker lives, then the production script in the subscription you read.",
			"On the worker, as root, run the command at the bottom. The browser does not start that scan.",
		}
	case "gcp":
		return []string{
			"This server uses Application Default Credentials. The form does not take a service-account key.",
			"Copy the inventory script and run it in Cloud Shell. It grants read roles on the project.",
			"Paste the project id, verify, then run the inventory scan.",
			"For packages on disks, run the scanner script in the project where the worker lives, then the production script in the project you read.",
			"On the worker, as root, run the command at the bottom. The browser does not start that scan.",
		}
	default:
		return nil
	}
}

func awsLinks(conn graph.CloudConnection) ([]Link, error) {
	inventory, err := quickCreate(conn.Region, "opensourceom-inventory", "aws/inventory/cloudformation.yaml", "aws-inventory", map[string]string{
		"ExternalId":   conn.ExternalID,
		"PrincipalArn": conn.InventoryPrincipal,
	})
	if err != nil {
		return nil, err
	}
	inventory.Label = "Inventory stack"
	inventory.Note = "Open this in the account you want to read. The output RoleArn is the inventory role."
	scanner, err := quickCreate(conn.Region, "opensourceom-worker", "aws/scanner/cloudformation.yaml", "aws-scanner", map[string]string{
		"ExternalId": conn.ExternalID,
	})
	if err != nil {
		return nil, err
	}
	scanner.Label = "Scanner stack"
	scanner.Note = "Open this in the account where the worker runs. Launch the worker with the instance profile from the output."
	production, err := quickCreate(conn.Region, "opensourceom-snapshot", "aws/production/cloudformation.yaml", "aws-production", map[string]string{
		"ExternalId":       conn.ExternalID,
		"ScannerRoleArn":   conn.ScannerPrincipal,
		"ScannerAccountId": conn.ScannerAccountID,
	})
	if err != nil {
		return nil, err
	}
	production.Label = "Production stack"
	production.Note = "Open this in the account you want to read. The output RoleArn is the snapshot role. Add the scanner principal to each key that encrypts a root volume."
	return []Link{inventory, scanner, production}, nil
}

func quickCreate(region, stack, templatePath, templateName string, params map[string]string) (Link, error) {
	if region == "" {
		region = "us-east-1"
	}
	template := TemplateBaseURL + templatePath
	link := fmt.Sprintf("https://console.aws.amazon.com/cloudformation/home?region=%s#/stacks/quickcreate?stackName=%s&templateURL=%s",
		url.QueryEscape(region),
		url.QueryEscape(stack),
		url.QueryEscape(template),
	)
	for _, key := range []string{"ExternalId", "PrincipalArn", "ScannerRoleArn", "ScannerAccountId"} {
		value := params[key]
		if value == "" {
			continue
		}
		link += "&param_" + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	return Link{URL: link, Template: templateName}, nil
}

type scriptLink struct {
	label    string
	template string
	note     string
	env      map[string]string
}

func scriptLinks(items []scriptLink) ([]Link, error) {
	links := make([]Link, 0, len(items))
	for _, item := range items {
		body, err := assets.ReadTemplate(item.template)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		for _, key := range envOrder(item.env) {
			value := item.env[key]
			if value == "" {
				continue
			}
			if looksLikeSecret(value) || strings.ContainsAny(value, " \t") {
				return nil, &Invalid{Message: "A value in the script is not safe to export."}
			}
			fmt.Fprintf(&b, "export %s='%s'\n", key, value)
		}
		b.Write(body)
		links = append(links, Link{
			Label:    item.label,
			Template: item.template,
			Script:   b.String(),
			Note:     item.note,
		})
	}
	return links, nil
}

func envOrder(env map[string]string) []string {
	order := []string{
		"AZURE_SUBSCRIPTION_ID", "AZURE_PRINCIPAL_ID", "AZURE_LOCATION", "AZURE_RESOURCE_GROUP", "SCANNER_PRINCIPAL_ID",
		"GCP_PROJECT_ID", "GCP_MEMBER", "SCANNER_SERVICE_ACCOUNT",
	}
	var keys []string
	seen := map[string]bool{}
	for _, key := range order {
		if _, ok := env[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	for key := range env {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	return keys
}

func awsWorkloadCommand(conn graph.CloudConnection) string {
	role := conn.SnapshotRoleARN
	if role == "" {
		role = "$ROLE_ARN"
	}
	return fmt.Sprintf("sudo -E om scan workload aws --snapshot-role %s --external-id %s --kms-key \"$SCANNER_KEY\"", role, conn.ExternalID)
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
