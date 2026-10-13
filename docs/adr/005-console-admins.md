<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 005: Console admins via Google and GitHub

**Status:** Accepted
**Date:** 2026-10-13

## Context

The console asked operators to paste `OM_API_SECRET` into the browser. That value is a deployment password shared by every person and every script. The OSS core has no user accounts, and [ADR 003](./003-phase2-cspm-rbac.md) kept SAML, roles, and enterprise identity out of this repo.

People using the console need a login. Collectors, CI, and Helm still need a credential that is not a person's session.

## Decision

- The console signs people in with Google or GitHub. There are no local passwords.
- An install with no admin prints a one-time setup link in the API log. The Google or GitHub account that completes it becomes the admin.
- An admin can create another one-time link. The account that completes it becomes an admin. The link expires after 72 hours and dies when it is used to create an account. An account that is already an admin does not consume the link.
- The stored identity is the provider plus that provider's stable subject (`sub` for Google, numeric user id for GitHub). Login and name are labels.
- Google accounts must have a verified email. Unverified Google accounts are rejected.
- A successful login sets an httpOnly session cookie. The cookie is `Secure` when `OM_PUBLIC_URL` is `https`. Sessions last 7 days.
- Every console account is an admin. There is no role column. The last admin cannot be removed.
- `GET /v1/admins`, `POST /v1/admins/invites`, and `DELETE /v1/admins/{id}` require a session. The API secret cannot create or remove admins.
- Other `/v1` routes accept the API secret or a session, except health, `GET /v1/auth/session`, and `POST /v1/auth/logout`.
- OAuth client id and secret are deployment configuration (`OM_GOOGLE_CLIENT_ID`, `OM_GOOGLE_CLIENT_SECRET`, `OM_GITHUB_CLIENT_ID`, `OM_GITHUB_CLIENT_SECRET`). Redirect URIs are `{OM_PUBLIC_URL}/auth/google/callback` and `{OM_PUBLIC_URL}/auth/github/callback`.
- SAML, custom OIDC issuers, group mapping, and non-admin roles stay outside this repo.

## Consequences

- Each install needs a Google OAuth client, a GitHub OAuth app, or both, plus a browser-facing `OM_PUBLIC_URL` and outbound HTTPS to those providers.
- An air-gapped console cannot sign anyone in until an enterprise identity provider exists outside this repo. Machine clients can still use `OM_API_SECRET`.
- The setup link is a secret in the API logs. Restarting the API before anyone uses it replaces the unused link. With more than one replica, use the latest link.
- Platform audit logs of who used the console remain a commercial concern. This ADR records who the admins are, not a history of their actions.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [ADR 003](./003-phase2-cspm-rbac.md)
