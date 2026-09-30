<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Architecture

> **Status:** Phase 3 in progress. The collector plugin SDK is available alongside Phase 2 CSPM rules, blast radius, Kubernetes ingest, and exports.

## Overview

```
┌─────────────┐     ┌────────────┐     ┌─────────────┐     ┌──────────┐
│ Cloud/K8s   │────▶│ Collectors │────▶│ Normalizer  │────▶│  Graph   │
│ APIs        │     │  (plugins) │     │  (schema)   │     │  Store   │
└─────────────┘     └────────────┘     └─────────────┘     └────┬─────┘
                                                                 │
          ┌────────────┐     ┌─────────────┐          ┌──────────┴────────┐
          │ Rules eng. │◀────│  Enrichment │◀─────────┤  Path + blast     │
          │  (CSPM)    │     │  (CVE/NVD)  │          │  radius queries   │
          └─────┬──────┘     └─────────────┘          └───────────────────┘
                │
          ┌─────▼──────┐     ┌─────────────┐     ┌──────────────┐
          │ Findings   │────▶│  API + UI   │────▶│ Export sinks │
          │ (w/ paths) │     │             │     │ Slack/SIEM/  │
          └────────────┘     └─────────────┘     │ Jira         │
                                                  └──────────────┘
```

## Implemented components

| Component | Location | Notes |
|-----------|----------|-------|
| **Collectors** | `internal/collectors/` | AWS, Azure, GCP, Kubernetes, demo; RDS, Azure SQL, and Cloud SQL are datastores; AWS emits CIS pack properties and recent CloudTrail management events |
| **Plugin SDK** | `sdk/collector`, `internal/plugins/` | External executables; `om scan plugin` |
| **Graph store** | `internal/graph/`, `migrations/` | PostgreSQL `nodes` + `edges` |
| **Path queries** | `internal/graph/query.go` | Named queries including `internet-to-datastore` and `internet-to-sensitive-datastore` |
| **Blast radius** | `internal/graph/blastradius.go` | Reachability from identities over `CAN_ACCESS` / `ASSUMES` |
| **CSPM rules** | `internal/rules/` | Built-in policies, embedded YAML packs, and attack-path findings |
| **CVE enrichment** | `internal/enrichment/` | Match workload packages and images, then NVD or a catalog for CVSS |
| **Exports** | `internal/export/` | SIEM JSONL, Slack webhooks, Jira issues |
| **API** | `internal/api/` | REST + embedded console at `/`; shared API secret on `/v1` except health |
| **CLI** | `cmd/om/`, `internal/cmd/` | `migrate`, `serve`, `scan`, `rules`, `identity`, `export`, … |
| **Helm** | `deploy/helm/opensourceom/` | API, optional Postgres, optional scheduled collectors |

## Graph schema (v0)

**Node types:** `Internet`, `Network`, `Workload`, `Identity`, `Datastore` (object storage and managed databases), `Finding`, `Control`

**Edge types:** `REACHABLE`, `ASSUMES`, `CAN_ACCESS`, `AFFECTS`, `VIOLATES`

Findings link to affected resources via `VIOLATES` edges. CSPM and CVE findings share the same `Finding` node type but use `finding_type` and `rule_id` / `cve_id` properties for provenance.

See [ADR 001](./adr/001-graph-schema-v0.md), [ADR 002](./adr/002-phase1-findings-ui.md), [ADR 003](./adr/003-phase2-cspm-rbac.md), and [ADR 004](./adr/004-collector-plugin-sdk.md).

## Technology choices

| Layer | Choice | Status |
|-------|--------|--------|
| Collectors | Go (AWS/Azure/GCP/K8s SDKs) plus out-of-process plugins | Shipped |
| Graph store | PostgreSQL | Shipped |
| CSPM rules | Go rule engine + graph context | Shipped |
| API | REST (`net/http`) + shared API secret | Shipped |
| UI | Embedded static HTML/JS (vis-network) | Shipped |
| Exports | Webhooks + JSONL + Jira REST | Shipped |
| Prod deployment | Kubernetes Helm chart | Shipped |

## Deployment

- **Dev:** Docker Compose — Postgres + API (`docker compose up -d`); CLI can also target Postgres directly
- **Prod:** Helm chart in `deploy/helm/opensourceom/` (API, optional Postgres, optional scheduled collectors)

## What's next (Phase 3)

Making the skeleton true, in order:

- Self-hosted operability (console). Read routes honor the API secret, and the Helm chart schedules collectors when credentials are set.
- CVE enrichment tied to workload inventory. `om enrich cve` writes a finding only when a workload package or image matches.
- Crown-jewel mark on datastores. A tag or label named `sensitivity` or `data-class` is stored on the datastore, and `internet-to-sensitive-datastore` keeps only those paths.
- Attack path as the finding. A rules run writes one `attack_path` finding per existing finding on an internet-reachable workload that can reach a datastore, and stores the path as ordered node ids.
- Cloud audit logs as graph context. `om scan aws` stores CloudTrail management events from the last 24 hours on the identity and resource they name, when that resource is on an exposed path. `GET /v1/graph/query` returns those events in `audits` for each path that contains the resource. Azure Activity Log, GCP Cloud Audit Logs, and S3 data events such as `GetObject` are not collected.

Further community rule packs (PCI and additional CIS mappings) stay open for contributors.

Issue links: [ROADMAP.md](./ROADMAP.md)

See the [website architecture page](https://opensourceom.org/docs/architecture/) for user-facing documentation.
