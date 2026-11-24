// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrCloudConnectionNotFound is returned when a connect id is missing.
var ErrCloudConnectionNotFound = errors.New("cloud connection not found")

// CloudConnection is a saved cloud setup. It stores role ARNs and an external
// id. It does not store access keys or client secrets.
type CloudConnection struct {
	ID                 string    `json:"id"`
	Provider           string    `json:"provider"`
	AccountID          string    `json:"account_id"`
	Region             string    `json:"region"`
	Location           string    `json:"location"`
	InventoryRoleARN   string    `json:"inventory_role_arn"`
	InventoryPrincipal string    `json:"inventory_principal"`
	ExternalID         string    `json:"external_id"`
	ScannerPrincipal   string    `json:"scanner_principal"`
	ScannerAccountID   string    `json:"scanner_account_id"`
	ResourceGroup      string    `json:"resource_group"`
	SnapshotRoleARN    string    `json:"snapshot_role_arn"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (s *Store) ListCloudConnections(ctx context.Context) ([]CloudConnection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, account_id, region, location, inventory_role_arn, inventory_principal,
			external_id, scanner_principal, scanner_account_id, resource_group, snapshot_role_arn, updated_at
		FROM cloud_connections
		ORDER BY updated_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudConnection
	for rows.Next() {
		conn, err := scanCloudConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, conn)
	}
	if out == nil {
		out = []CloudConnection{}
	}
	return out, rows.Err()
}

func (s *Store) GetCloudConnection(ctx context.Context, id string) (CloudConnection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, account_id, region, location, inventory_role_arn, inventory_principal,
			external_id, scanner_principal, scanner_account_id, resource_group, snapshot_role_arn, updated_at
		FROM cloud_connections
		WHERE id = $1`, id)
	if err != nil {
		return CloudConnection{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return CloudConnection{}, err
		}
		return CloudConnection{}, ErrCloudConnectionNotFound
	}
	return scanCloudConnection(rows)
}

func (s *Store) InsertCloudConnection(ctx context.Context, conn CloudConnection) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cloud_connections (
			id, provider, account_id, region, location, inventory_role_arn, inventory_principal,
			external_id, scanner_principal, scanner_account_id, resource_group, snapshot_role_arn, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())`,
		conn.ID, conn.Provider, conn.AccountID, conn.Region, conn.Location, conn.InventoryRoleARN,
		conn.InventoryPrincipal, conn.ExternalID, conn.ScannerPrincipal, conn.ScannerAccountID,
		conn.ResourceGroup, conn.SnapshotRoleARN)
	if err != nil {
		return fmt.Errorf("insert cloud connection: %w", err)
	}
	return nil
}

func (s *Store) UpdateCloudConnection(ctx context.Context, conn CloudConnection) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE cloud_connections SET
			account_id = $2,
			region = $3,
			location = $4,
			inventory_role_arn = $5,
			inventory_principal = $6,
			scanner_principal = $7,
			scanner_account_id = $8,
			resource_group = $9,
			snapshot_role_arn = $10,
			updated_at = now()
		WHERE id = $1`,
		conn.ID, conn.AccountID, conn.Region, conn.Location, conn.InventoryRoleARN,
		conn.InventoryPrincipal, conn.ScannerPrincipal, conn.ScannerAccountID,
		conn.ResourceGroup, conn.SnapshotRoleARN)
	if err != nil {
		return fmt.Errorf("update cloud connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrCloudConnectionNotFound
	}
	return nil
}

func (s *Store) DeleteCloudConnection(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM cloud_connections WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCloudConnectionNotFound
	}
	return nil
}

type cloudConnectionRow interface {
	Scan(dest ...any) error
}

func scanCloudConnection(row cloudConnectionRow) (CloudConnection, error) {
	var conn CloudConnection
	err := row.Scan(
		&conn.ID, &conn.Provider, &conn.AccountID, &conn.Region, &conn.Location,
		&conn.InventoryRoleARN, &conn.InventoryPrincipal, &conn.ExternalID,
		&conn.ScannerPrincipal, &conn.ScannerAccountID, &conn.ResourceGroup,
		&conn.SnapshotRoleARN, &conn.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CloudConnection{}, ErrCloudConnectionNotFound
	}
	return conn, err
}
