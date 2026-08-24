<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# API

HTTP and GraphQL API for the web UI, collectors, and integrations.

## Planned endpoints

- `POST /v1/ingest` — batch node/edge ingestion from collectors
- `GET /v1/graph/query` — attack path and neighborhood queries
- `GET /v1/findings` — prioritized findings with path context
- `GET /v1/health` — readiness for orchestration

Authentication: API keys in dev; OIDC / mTLS for production (planned).
