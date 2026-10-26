// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const metadataURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

var metadataClient = &http.Client{
	Timeout:   2 * time.Second,
	Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }},
}

// LookupWorker reads this VM's identity from the instance metadata service.
func LookupWorker(ctx context.Context) (Worker, error) {
	body, err := fetchMetadata(ctx)
	if err != nil {
		return Worker{}, fmt.Errorf("om scan workload azure runs on an Azure VM in this subscription: %w", err)
	}
	worker, err := parseMetadata(body)
	if err != nil {
		return Worker{}, err
	}
	return worker, nil
}

func fetchMetadata(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
	resp, err := metadataClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("instance metadata returned %s", resp.Status)
	}
	return body, nil
}

func parseMetadata(body []byte) (Worker, error) {
	var doc struct {
		Compute struct {
			Location          string `json:"location"`
			Name              string `json:"name"`
			ResourceGroupName string `json:"resourceGroupName"`
			SubscriptionID    string `json:"subscriptionId"`
			Zone              string `json:"zone"`
		} `json:"compute"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Worker{}, fmt.Errorf("parse instance metadata: %w", err)
	}
	worker := Worker{
		Name:           doc.Compute.Name,
		ResourceGroup:  doc.Compute.ResourceGroupName,
		SubscriptionID: doc.Compute.SubscriptionID,
		Location:       normalizeLocation(doc.Compute.Location),
		Zone:           strings.TrimSpace(doc.Compute.Zone),
	}
	if worker.Name == "" || worker.ResourceGroup == "" || worker.SubscriptionID == "" || worker.Location == "" {
		return Worker{}, fmt.Errorf("instance metadata is missing the VM name, resource group, subscription, or location")
	}
	return worker, nil
}

// CheckSubscription reports when this VM is in a different subscription than AZURE_SUBSCRIPTION_ID.
func CheckSubscription(workerSub, configured string) error {
	if workerSub == "" || configured == "" {
		return fmt.Errorf("Azure subscription is empty")
	}
	if !strings.EqualFold(workerSub, configured) {
		return fmt.Errorf("this VM is in subscription %s; set AZURE_SUBSCRIPTION_ID=%s", workerSub, workerSub)
	}
	return nil
}
