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

Authentication: when `OM_API_SECRET` is set, every `/v1/*` route except `GET /v1/health`, `GET /v1/auth/session`, and `POST /v1/auth/logout` requires `Authorization: Bearer`, `X-API-Key`, or a console session cookie. An empty secret leaves those graph routes open for local development. Admin routes (`/v1/admins`) require the session even when the caller has the API secret. The console signs people in with Google or GitHub. Enterprise SAML and custom identity providers live outside this repo.
