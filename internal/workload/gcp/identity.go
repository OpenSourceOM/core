// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/compute/metadata"
)

type metaAPI interface {
	OnGCE(ctx context.Context) bool
	ProjectID(ctx context.Context) (string, error)
	InstanceName(ctx context.Context) (string, error)
	Zone(ctx context.Context) (string, error)
}

type gceMeta struct{}

func (gceMeta) OnGCE(ctx context.Context) bool { return metadata.OnGCEWithContext(ctx) }
func (gceMeta) ProjectID(ctx context.Context) (string, error) {
	return metadata.ProjectIDWithContext(ctx)
}
func (gceMeta) InstanceName(ctx context.Context) (string, error) {
	return metadata.InstanceNameWithContext(ctx)
}
func (gceMeta) Zone(ctx context.Context) (string, error) { return metadata.ZoneWithContext(ctx) }

// LookupWorker reads this instance's project, name, and zone from the metadata server.
func LookupWorker(ctx context.Context) (Worker, error) {
	return lookupWorker(ctx, gceMeta{})
}

func lookupWorker(ctx context.Context, meta metaAPI) (Worker, error) {
	if !meta.OnGCE(ctx) {
		return Worker{}, fmt.Errorf("om scan workload gcp runs on a GCE instance in this project")
	}
	project, err := meta.ProjectID(ctx)
	if err != nil {
		return Worker{}, fmt.Errorf("read project: %w", err)
	}
	name, err := meta.InstanceName(ctx)
	if err != nil {
		return Worker{}, fmt.Errorf("read instance name: %w", err)
	}
	zone, err := meta.Zone(ctx)
	if err != nil {
		return Worker{}, fmt.Errorf("read zone: %w", err)
	}
	zone = lastSegment(zone)
	if project == "" || name == "" || zone == "" {
		return Worker{}, fmt.Errorf("instance metadata is missing the project, name, or zone")
	}
	return Worker{Name: name, ProjectID: project, Zone: zone}, nil
}

// CheckProject reports when this instance is in a different project than GCP_PROJECT_ID.
func CheckProject(workerProject, configured string) error {
	if workerProject == "" || configured == "" {
		return fmt.Errorf("GCP project is empty")
	}
	if workerProject != configured {
		return fmt.Errorf("this instance is in project %s; set GCP_PROJECT_ID=%s", workerProject, workerProject)
	}
	return nil
}
