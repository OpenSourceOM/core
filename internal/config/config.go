// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Env         string
	LogLevel    string
	PublicURL   string
	APIPort     int
	APISecret   string
	DatabaseURL string
	AWSRegion             string
	AzureSubscriptionID   string
	AzureLocation         string
	GCPProjectID          string
	GCPRegion             string
	NVDAPIKey             string
	K8sCluster            string
	K8sNamespace          string
	SlackWebhookURL       string
	JiraURL               string
	JiraEmail             string
	JiraAPIToken          string
	JiraProject           string
}

func Load() Config {
	port, _ := strconv.Atoi(getEnv("OM_API_PORT", "8080"))
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
		Env:         getEnv("OM_ENV", "development"),
		LogLevel:    getEnv("OM_LOG_LEVEL", "info"),
		PublicURL:   getEnv("OM_PUBLIC_URL", "http://localhost:8080"),
		APIPort:     port,
		APISecret:   getEnv("OM_API_SECRET", "change-me-in-production"),
		DatabaseURL:         databaseURL,
		AWSRegion:           getEnv("AWS_REGION", "us-east-1"),
		AzureSubscriptionID: getEnv("AZURE_SUBSCRIPTION_ID", ""),
		AzureLocation:       getEnv("AZURE_LOCATION", "eastus"),
		GCPProjectID:        getEnv("GCP_PROJECT_ID", ""),
		GCPRegion:           getEnv("GCP_REGION", "us-central1"),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		K8sCluster:          getEnv("K8S_CLUSTER", "default"),
		K8sNamespace:          getEnv("K8S_NAMESPACE", ""),
		SlackWebhookURL:       getEnv("SLACK_WEBHOOK_URL", ""),
		JiraURL:               getEnv("JIRA_URL", ""),
		JiraEmail:             getEnv("JIRA_EMAIL", ""),
		JiraAPIToken:          getEnv("JIRA_API_TOKEN", ""),
		JiraProject:           getEnv("JIRA_PROJECT", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
