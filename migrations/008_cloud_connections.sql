-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- Saved cloud connect settings. Role ARNs and an external id are not access keys.

CREATE TABLE cloud_connections (
    id text PRIMARY KEY,
    provider text NOT NULL,
    account_id text NOT NULL DEFAULT '',
    region text NOT NULL DEFAULT '',
    location text NOT NULL DEFAULT '',
    inventory_role_arn text NOT NULL DEFAULT '',
    inventory_principal text NOT NULL DEFAULT '',
    external_id text NOT NULL DEFAULT '',
    scanner_principal text NOT NULL DEFAULT '',
    scanner_account_id text NOT NULL DEFAULT '',
    resource_group text NOT NULL DEFAULT '',
    snapshot_role_arn text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
