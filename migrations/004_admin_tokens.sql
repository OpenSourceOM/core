-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- Personal API tokens and email invites. The shared deployment secret is not used.

ALTER TABLE admins ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN IF NOT EXISTS api_token_hash TEXT;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS api_token_preview TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_api_token
  ON admins (api_token_hash)
  WHERE api_token_hash IS NOT NULL;

ALTER TABLE admin_invites ADD COLUMN IF NOT EXISTS email TEXT;
