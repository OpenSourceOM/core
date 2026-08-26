<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# OpenSourceOM Core

[![CI](https://github.com/OpenSourceOM/core/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenSourceOM/core/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OpenSourceOM/core/actions/workflows/codeql.yml/badge.svg)](https://github.com/OpenSourceOM/core/actions/workflows/codeql.yml)
[![Snyk](https://github.com/OpenSourceOM/core/actions/workflows/snyk.yml/badge.svg)](https://github.com/OpenSourceOM/core/actions/workflows/snyk.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/OpenSourceOM/core?include_prereleases)](https://github.com/OpenSourceOM/core/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-opensourceom%2Fcore-blue?logo=docker&logoColor=white)](https://github.com/OpenSourceOM/core/pkgs/container/core)

**Self-hosted, graph-native cloud security — prioritize what attackers can actually reach.**

OpenSourceOM Core is the platform behind [OpenSourceOM](https://opensourceom.org): collectors that ingest cloud inventory and security signals, a graph engine that models attack paths, and APIs/UI to explore risk in context.

Traditional scanners flood you with CVEs and misconfigurations. OpenSourceOM connects the dots — showing which findings sit on paths from the internet to your sensitive data and privileged identities.

> **Status:** Early development (Phase 2). CSPM rules, identity blast radius, Kubernetes ingest, and export integrations are available. See the [roadmap](./docs/ROADMAP.md) for Phase 3.

## Why this exists

CNAPP platforms demonstrated that **context beats volume**: a critical CVE on an isolated dev box is not the same as a high-severity issue on an internet-exposed path to production.

OpenSourceOM brings that graph-first model to teams that want:

- **Transparency** — inspect scoring, rules, and enrichment in code
- **Control** — run entirely in your VPC
- **Community** — extend collectors and policies without vendor lock-in

## What Core does

| Capability | Description |
|------------|-------------|
| **Security graph** | Model workloads, identities, network paths, data stores, and findings as nodes and edges |
| **Attack path analysis** | Query reachable paths — e.g. internet → CVE → prod database |
| **Risk prioritization** | Rank findings by exposure, blast radius, and path length — not CVSS alone |
| **CSPM** | Graph-context policy rules with prioritized findings |
| **Multi-cloud** | AWS, Azure, GCP, and Kubernetes collectors |

## Architecture

```
Cloud APIs → Collectors → Normalizer → Graph Store → API / UI
                              ↘ Rules Engine → Findings (with path context)
```

**Graph schema (v0):** nodes like `Workload`, `Identity`, `Datastore`, `Finding`; edges like `REACHABLE`, `ASSUMES`, `AFFECTS`.

Full design: [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)

## Repository layout

```
cmd/om/              `om` CLI (migrate, serve, scan, enrich, rules, identity, export)
internal/collectors/ AWS, Azure, GCP, Kubernetes, demo graph
packs/               Embedded YAML CSPM rule packs
internal/rules/      CSPM rules engine with graph-context scoring
internal/graph/      Graph schema, Postgres store, path + blast-radius queries
internal/enrichment/ CVE lookup (NVD) and severity normalization
internal/export/     Slack, SIEM, Jira exporters
internal/api/        REST API + embedded web console
migrations/          Postgres schema migrations
docs/                Architecture, roadmap, ADRs
docker-compose.yml   Local dev stack (Postgres + API)
deploy/helm/         Production Kubernetes chart
```

## Quick start

Phase 2 stack — Postgres, multi-cloud + Kubernetes collectors, CSPM rules, CVE enrichment, blast-radius analysis, exports, and a web console.

```bash
git clone https://github.com/OpenSourceOM/core.git
cd core
cp .env.example .env

# Start Postgres + API (http://localhost:8080)
docker compose up -d

# Build the CLI
go build -o om ./cmd/om

# Apply graph schema migrations
./om migrate

# Load the sample graph (no cloud credentials)
./om scan demo

# Or scan cloud / cluster inventory
export AWS_REGION=us-east-1
./om scan aws
./om scan k8s      # requires kubeconfig

# Run CSPM rules (builtin graph-context + embedded packs)
./om rules list
./om rules run

# Identity blast radius
./om identity blast-radius --name AdminRole

# Enrich with CVE data (NVD API)
./om enrich cve --cve CVE-2021-44228

# Export findings
./om export findings run --format siem --out findings.jsonl

# Open the web console (click identities for blast radius)
open http://localhost:8080
```

**API endpoints:** `GET /v1/health`, `POST /v1/ingest`, `GET /v1/findings`, `GET /v1/graph/snapshot`, `POST /v1/rules/run`, `GET /v1/identity/blast-radius`

**Multi-cloud scan:**

```bash
./om scan demo     # sample environment, no credentials
./om scan aws
./om scan azure    # requires AZURE_SUBSCRIPTION_ID + az login
./om scan gcp      # requires GCP_PROJECT_ID + ADC
./om scan k8s      # requires kubeconfig or in-cluster credentials
```

For local CLI-only use without Docker API, run `docker compose up -d postgres` and set `POSTGRES_HOST=localhost`.

**Kubernetes:**

```bash
docker build -t ghcr.io/opensourceom/core:0.1.0 .
helm install om deploy/helm/opensourceom \
  --set api.secret='change-me' \
  --set postgres.password='change-me' \
  --set image.tag=0.1.0
```

Documentation: [opensourceom.org/docs](https://opensourceom.org/docs/)

## Roadmap snapshot

| Phase | Focus |
|-------|--------|
| **0** | Graph schema v0, AWS collector, ingest API, `om` CLI |
| **1** | Attack path queries, CVE enrichment, web UI, Azure/GCP collectors |
| **2** *(now)* | CSPM rules, blast radius, K8s connector, exports |
| **3** | Plugin SDK, Helm chart, community rule packs |

Details: [docs/ROADMAP.md](./docs/ROADMAP.md)

## Contributing

We welcome issues, discussions, and PRs.

1. Read the [roadmap](./docs/ROADMAP.md) and [architecture](./docs/ARCHITECTURE.md)
2. Open a [discussion](https://github.com/OpenSourceOM/core/discussions) before large changes
3. Keep collectors **read-only** toward cloud accounts by default
4. See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Related repositories

| Repo | Purpose |
|------|---------|
| [website](https://github.com/OpenSourceOM/website) | Marketing site and user docs |
| [core](https://github.com/OpenSourceOM/core) | This repository |

## Security

Report vulnerabilities to **security@opensourceom.org**. Do not open public issues for security bugs. See [SECURITY.md](./SECURITY.md).

## License

Apache-2.0 — see [LICENSE](./LICENSE).
