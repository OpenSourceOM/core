-- Copyright 2026 OpenSourceOM
-- SPDX-License-Identifier: Apache-2.0
-- Phase 1: indexes for findings and graph UI queries

CREATE INDEX IF NOT EXISTS idx_nodes_properties_severity
  ON nodes ((properties->>'severity'))
  WHERE type = 'Finding';

CREATE INDEX IF NOT EXISTS idx_nodes_properties_cve
  ON nodes ((properties->>'cve_id'))
  WHERE type = 'Finding';
