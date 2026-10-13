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

Authentication: every `/v1/*` route except `GET /v1/health`, `GET /v1/auth/session`, and `POST /v1/auth/logout` requires a console session cookie or that admin's personal API token (`Authorization: Bearer` or `X-API-Key`). Admin routes (`/v1/admins`, including invites and token rotation) require the session. The console signs people in with Google or GitHub. The first sign-in becomes the admin. Later admins join from an email invite whose address must match a verified provider email. Enterprise SAML and custom identity providers live outside this repo.
