-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- API tokens are created on request. Drop secrets that were stored and never shown.

UPDATE admins
SET api_token_hash = NULL
WHERE api_token_preview IS NOT NULL AND btrim(api_token_preview) <> '';

ALTER TABLE admins DROP COLUMN IF EXISTS api_token_preview;
