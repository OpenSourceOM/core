// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env                 string
	LogLevel            string
	PublicURL           string
	APIPort             int
	GoogleClientID      string
	GoogleClientSecret  string
	GitHubClientID      string
	GitHubClientSecret  string
	SMTPHost            string
	SMTPPort            int
	SMTPUsername        string
	SMTPPassword        string
	SMTPFrom            string
	AdminEmail          string
	DatabaseURL         string
	AWSRegion           string
	AzureSubscriptionID string
	AzureLocation       string
	GCPProjectID        string
	GCPRegion           string
	NVDAPIKey           string
	CVECatalog          string
	K8sCluster          string
	K8sNamespace        string
	SlackWebhookURL     string
	JiraURL             string
	JiraEmail           string
	JiraAPIToken        string
	JiraProject         string
}

func Load() Config {
	port, _ := strconv.Atoi(getEnv("OM_API_PORT", "8080"))
	smtpPort, _ := strconv.Atoi(getEnv("OM_SMTP_PORT", "587"))
	user := getEnv("POSTGRES_USER", "opensourceom")
	pass := getEnv("POSTGRES_PASSWORD", "opensourceom")
	db := getEnv("POSTGRES_DB", "opensourceom")
	host := getEnv("POSTGRES_HOST", "localhost")
	pgPort := getEnv("POSTGRES_PORT", "5432")

	databaseURL := getEnv("DATABASE_URL", "")
	if databaseURL == "" {
		databaseURL = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=disable",
			user, pass, host, pgPort, db,
		)
	}

	return Config{
		Env:                 getEnv("OM_ENV", "development"),
		LogLevel:            getEnv("OM_LOG_LEVEL", "info"),
		PublicURL:           getEnv("OM_PUBLIC_URL", "http://localhost:8080"),
		APIPort:             port,
		GoogleClientID:      getEnv("OM_GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:  getEnv("OM_GOOGLE_CLIENT_SECRET", ""),
		GitHubClientID:      getEnv("OM_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:  getEnv("OM_GITHUB_CLIENT_SECRET", ""),
		SMTPHost:            getEnv("OM_SMTP_HOST", ""),
		SMTPPort:            smtpPort,
		SMTPUsername:        getEnv("OM_SMTP_USERNAME", ""),
		SMTPPassword:        getEnv("OM_SMTP_PASSWORD", ""),
		SMTPFrom:            getEnv("OM_SMTP_FROM", ""),
		AdminEmail:          getEnv("OM_ADMIN_EMAIL", ""),
		DatabaseURL:         databaseURL,
		AWSRegion:           getEnv("AWS_REGION", "us-east-1"),
		AzureSubscriptionID: getEnv("AZURE_SUBSCRIPTION_ID", ""),
		AzureLocation:       getEnv("AZURE_LOCATION", "eastus"),
		GCPProjectID:        getEnv("GCP_PROJECT_ID", ""),
		GCPRegion:           getEnv("GCP_REGION", "us-central1"),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		CVECatalog:          getEnv("OM_CVE_CATALOG", ""),
		K8sCluster:          getEnv("K8S_CLUSTER", "default"),
		K8sNamespace:        getEnv("K8S_NAMESPACE", ""),
		SlackWebhookURL:     getEnv("SLACK_WEBHOOK_URL", ""),
		JiraURL:             getEnv("JIRA_URL", ""),
		JiraEmail:           getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:        getEnv("JIRA_API_TOKEN", ""),
		JiraProject:         getEnv("JIRA_PROJECT", ""),
	}
}

// ServeAutoMigrate reports whether om serve applies pending migrations before it listens.
// An unset or empty OM_AUTO_MIGRATE means yes. A present value must be a boolean.
func ServeAutoMigrate() (bool, error) {
	raw, ok := os.LookupEnv("OM_AUTO_MIGRATE")
	if !ok || strings.TrimSpace(raw) == "" {
		return true, nil
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("OM_AUTO_MIGRATE=%q is not a boolean", raw)
	}
	return value, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
