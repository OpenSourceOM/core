-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- Email and password admins. Google and GitHub stay optional.

ALTER TABLE admins DROP CONSTRAINT IF EXISTS admins_provider_check;
ALTER TABLE admins ADD CONSTRAINT admins_provider_check
  CHECK (provider IN ('google', 'github', 'password'));

ALTER TABLE admins ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS recovery_hashes TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_password_email
  ON admins (lower(email))
  WHERE provider = 'password' AND email <> '';

CREATE TABLE IF NOT EXISTS admin_login_challenges (
  id TEXT PRIMARY KEY,
  admin_id UUID NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);
