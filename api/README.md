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
- `GET /v1/version` — version, git commit, and commit date of this build

Authentication: every `/v1/*` route except `GET /v1/health`, `GET /v1/version`, `GET /v1/auth/session`, `POST /v1/auth/logout`, `POST /v1/auth/setup`, `POST /v1/auth/login`, and `POST /v1/auth/totp` requires a console session cookie or an API token that admin created (`Authorization: Bearer` or `X-API-Key`). Admin routes (`/v1/admins`, including token create and rotation) require the session. People sign in with email and password. The first account is created from the setup form or `om admin create`. A token is created from the console or `om token create`, and is not issued at sign-in. Google and GitHub are optional and must match an existing admin email. Enterprise SAML and custom identity providers live outside this repo.
