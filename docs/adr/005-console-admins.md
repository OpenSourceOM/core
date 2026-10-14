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

- The console signs people in with an email and password. Passwords are stored as Argon2id hashes. There is no shared deployment secret.
- While no admin exists, the console shows a setup form. `OM_ADMIN_EMAIL`, when set, is the only address that form accepts. `om admin create --email` creates that account from the machine before the port is reachable. Keep the port private until an admin exists.
- An admin adds the next admin by email. The new account gets a temporary password, shown once in the console, and must choose a new password at the next sign-in. SMTP is optional. When it is configured, the temporary password is emailed as well, and the sign-in page can email a password-reset link. The link works once, expires in one hour, and does not say whether the address is an admin. Using it sets a new password and ends that admin's sessions. Personal API tokens stay valid. Without SMTP, the page does not offer reset. `om admin reset-password --email` still sets a password from the machine.
- Google and GitHub are optional. Buttons appear only when that provider's client id and secret are set. A verified email from the provider must match an existing admin. A new provider account does not become an admin on its own.
- Each admin can turn on TOTP two-factor authentication. Recovery codes are shown once. It is not required to finish setup.
- Google accounts must have a verified email. GitHub login requests `user:email` and accepts any verified address.
- A successful login sets an httpOnly session cookie. The cookie is `Secure` when `OM_PUBLIC_URL` is `https`. Sessions last 7 days.
- Creating an admin does not create an API token. An admin creates one from the console, or from the machine with `om token create --email`. The database stores only the hash. The raw value is shown once, in that response. Scripts send it as `Authorization: Bearer` or `X-API-Key`. Rotating the token, from the console or `om token rotate --email`, returns the new value once and invalidates the old one. Removing an admin revokes their token.
- Every console account is an admin. There is no role column. The last admin cannot be removed.
- `GET /v1/admins`, `POST /v1/admins`, `POST /v1/admins/token`, and `DELETE /v1/admins/{id}` require a session. A personal token cannot create, rotate, or remove admins.
- Other `/v1` routes accept that personal token or a session, except health, `GET /v1/auth/session`, and `POST /v1/auth/logout`. There is no shared secret and no open mode.
- OAuth client id and secret are deployment configuration (`OM_GOOGLE_CLIENT_ID`, `OM_GOOGLE_CLIENT_SECRET`, `OM_GITHUB_CLIENT_ID`, `OM_GITHUB_CLIENT_SECRET`). Redirect URIs are `{OM_PUBLIC_URL}/auth/google/callback` and `{OM_PUBLIC_URL}/auth/github/callback`.
- SAML, custom OIDC issuers, group mapping, and non-admin roles stay outside this repo.

## Consequences

- Password login works with no identity provider and no mail server. Google, GitHub, and SMTP are optional.
- Whoever can reach the API before the first admin exists can claim the install. Keep that port private, or create the admin with `om admin create` first.
- An air-gapped console can sign in with a password. Scripts need a token created from the console or with `om token create`.
- Platform audit logs of who used the console remain a commercial concern. This ADR records who the admins are, not a history of their actions.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [ADR 003](./003-phase2-cspm-rbac.md)
