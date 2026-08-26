<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Architecture

> **Status:** Phase 2 shipped. CSPM rules with graph-context scoring, identity blast radius, Kubernetes ingest, and export integrations are implemented alongside Phase 1 collectors, enrichment, and the web console.

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
| **Collectors** | `internal/collectors/` | AWS, Azure, GCP, Kubernetes, demo; AWS emits CIS pack properties |
| **Graph store** | `internal/graph/`, `migrations/` | PostgreSQL `nodes` + `edges` |
| **Path queries** | `internal/graph/query.go` | Named queries including `internet-to-datastore` |
| **Blast radius** | `internal/graph/blastradius.go` | Reachability from identities over `CAN_ACCESS` / `ASSUMES` |
| **CSPM rules** | `internal/rules/` | Built-in policies plus embedded YAML packs |
| **CVE enrichment** | `internal/enrichment/` | NVD lookup, CVSS → normalized severity |
| **Exports** | `internal/export/` | SIEM JSONL, Slack webhooks, Jira issues |
| **API** | `internal/api/` | REST + embedded console at `/`; shared API secret for writes |
| **CLI** | `cmd/om/`, `internal/cmd/` | `migrate`, `serve`, `scan`, `rules`, `identity`, `export`, … |
| **Helm** | `deploy/helm/opensourceom/` | API + optional in-cluster Postgres |

## Graph schema (v0)

**Node types:** `Internet`, `Network`, `Workload`, `Identity`, `Datastore`, `Finding`, `Control`

**Edge types:** `REACHABLE`, `ASSUMES`, `CAN_ACCESS`, `AFFECTS`, `VIOLATES`

Findings link to affected resources via `VIOLATES` edges. CSPM and CVE findings share the same `Finding` node type but use `finding_type` and `rule_id` / `cve_id` properties for provenance.

See [ADR 001](./adr/001-graph-schema-v0.md), [ADR 002](./adr/002-phase1-findings-ui.md), and [ADR 003](./adr/003-phase2-cspm-rbac.md).

## Technology choices

| Layer | Choice | Status |
|-------|--------|--------|
| Collectors | Go (AWS/Azure/GCP/K8s SDKs) | Shipped |
| Graph store | PostgreSQL | Shipped |
| CSPM rules | Go rule engine + graph context | Shipped |
| API | REST (`net/http`) + shared API secret | Shipped |
| UI | Embedded static HTML/JS (vis-network) | Shipped |
| Exports | Webhooks + JSONL + Jira REST | Shipped |
| Prod deployment | Kubernetes Helm chart | Shipped |

## Deployment

- **Dev:** Docker Compose — Postgres + API (`docker compose up -d`); CLI can also target Postgres directly
- **Prod:** Helm chart in `deploy/helm/opensourceom/` (API + optional Postgres)

## What's next (Phase 3)

- Plugin SDK for custom collectors
- Broader community rule packs (PCI and additional CIS mappings)

Details: [ROADMAP.md](./ROADMAP.md)

See the [website architecture page](https://opensourceom.org/docs/architecture/) for user-facing documentation.
