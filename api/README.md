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

Authentication: when `OM_API_SECRET` is set, every `/v1/*` route except `GET /v1/health` requires `Authorization: Bearer` or `X-API-Key`. An empty secret leaves the API open for local development. The console sends `X-API-Key` from `localStorage.om_api_key`. SSO and other enterprise identity integrations are commercial and live outside this repo.
