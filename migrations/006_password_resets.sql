-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- One-time password reset links. The raw token is emailed; only its hash is stored.

CREATE TABLE IF NOT EXISTS admin_password_resets (
  id TEXT PRIMARY KEY,
  admin_id UUID NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_password_resets_admin
  ON admin_password_resets (admin_id);
