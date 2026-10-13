<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 005: Console admins via Google and GitHub

**Status:** Accepted
**Date:** 2026-10-13

## Context

The console asked operators to paste a shared deployment secret into the browser. That value was a password shared by every person and every script. The OSS core has no user accounts, and [ADR 003](./003-phase2-cspm-rbac.md) kept SAML, roles, and enterprise identity out of this repo.

People using the console need a login. Scripts that call the HTTP API need a credential that is not a person's session. The CLI talks to Postgres and does not use that credential.

## Decision

- The console signs people in with Google or GitHub. There are no local passwords.
- The first successful Google or GitHub sign-in, while no admin exists, becomes the admin. Keep the API port private until that login. A later sign-in with no matching invite is rejected.
- An admin invites the next admin by email. The invite stores that address. The recipient opens the link and signs in with Google or GitHub. A verified email from the provider must match the invite, ignoring case. GitHub login requests `user:email` and accepts any verified address, not only the primary one.
- Sending the invite requires SMTP (`OM_SMTP_HOST`, `OM_SMTP_PORT`, `OM_SMTP_USERNAME`, `OM_SMTP_PASSWORD`, `OM_SMTP_FROM`). The message contains the link, not an API token. If the message cannot be sent, the unused invite is discarded. Invites expire after 72 hours. An account that is already an admin does not consume the invite.
- The stored identity is the provider plus that provider's stable subject (`sub` for Google, numeric user id for GitHub). Login, name, and email are labels.
- Google accounts must have a verified email. Accounts with no verified email are rejected.
- A successful login sets an httpOnly session cookie. The cookie is `Secure` when `OM_PUBLIC_URL` is `https`. Sessions last 7 days.
- Creating an admin also creates a personal API token. The database stores only the hash. The raw value is shown once, in the console after that first session. Scripts send it as `Authorization: Bearer` or `X-API-Key`. Rotating the token returns the new value once and invalidates the old one. Removing an admin revokes their token.
- Every console account is an admin. There is no role column. The last admin cannot be removed.
- `GET /v1/admins`, `POST /v1/admins/invites`, `POST /v1/admins/token`, and `DELETE /v1/admins/{id}` require a session. A personal token cannot create, rotate, or remove admins.
- Other `/v1` routes accept that personal token or a session, except health, `GET /v1/auth/session`, and `POST /v1/auth/logout`. There is no shared secret and no open mode.
- OAuth client id and secret are deployment configuration (`OM_GOOGLE_CLIENT_ID`, `OM_GOOGLE_CLIENT_SECRET`, `OM_GITHUB_CLIENT_ID`, `OM_GITHUB_CLIENT_SECRET`). Redirect URIs are `{OM_PUBLIC_URL}/auth/google/callback` and `{OM_PUBLIC_URL}/auth/github/callback`.
- SAML, custom OIDC issuers, group mapping, and non-admin roles stay outside this repo.

## Consequences

- Each install needs a Google OAuth client, a GitHub OAuth app, or both, plus a browser-facing `OM_PUBLIC_URL` and outbound HTTPS to those providers. Inviting another admin also needs SMTP.
- Whoever can reach the API before the first login can become the admin. Keep that port private until the first admin exists.
- An air-gapped console cannot sign anyone in until an enterprise identity provider exists outside this repo. Scripts need a personal token from an admin who has signed in.
- Platform audit logs of who used the console remain a commercial concern. This ADR records who the admins are, not a history of their actions.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [ADR 003](./003-phase2-cspm-rbac.md)
