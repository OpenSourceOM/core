<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to OpenSourceOM Core

Thank you for helping build open cloud security tooling.

## Getting started

1. Fork and clone the repo
2. Copy `.env.example` to `.env`
3. Run `docker compose up -d` for local Postgres
4. Pick an item from [docs/ROADMAP.md](./docs/ROADMAP.md) or open a discussion

## Development guidelines

- Keep collectors **read-only** toward cloud accounts by default
- Document graph schema changes in `docs/`
- Prefer small, reviewable PRs
- Add tests for graph queries and normalization logic

## Code of conduct

Be respectful and constructive. We are building infrastructure security tools — clarity and safety matter.

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
