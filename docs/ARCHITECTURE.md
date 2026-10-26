<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Architecture

> **Status:** Phase 3 has shipped. The collector plugin SDK, Helm, the embedded rule pack, and cloud audit context from CloudTrail, Activity Log, and Admin Activity logs are in the tree, alongside Phase 2 CSPM rules, blast radius, Kubernetes ingest, and exports. Phase 4 is open: `om scan workload` inventories AWS, Azure, and GCE Linux root volumes. Phase 5 (secret and malware findings on that storage) is open. Further rule packs stay open for contributors.

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
| **Collectors** | `internal/collectors/` | AWS, Azure, GCP, Kubernetes, demo; RDS, Azure SQL, and Cloud SQL are datastores; AWS emits CIS pack properties and recent CloudTrail management events; Azure emits recent Activity Log events; GCP emits recent Admin Activity audit logs |
| **Workload packages** | `internal/workload/` | `om scan workload` reads AWS, Azure, and GCE Linux root volumes and sets `packages` |
| **Plugin SDK** | `sdk/collector`, `internal/plugins/` | External executables; `om scan plugin` |
| **Graph store** | `internal/graph/`, `migrations/` | PostgreSQL `nodes` + `edges` |
| **Path queries** | `internal/graph/query.go` | Named queries including `internet-to-datastore` and `internet-to-sensitive-datastore` |
| **Blast radius** | `internal/graph/blastradius.go` | Reachability from identities over `CAN_ACCESS` / `ASSUMES` |
| **CSPM rules** | `internal/rules/` | Built-in policies, embedded YAML packs, and attack-path findings |
| **CVE enrichment** | `internal/enrichment/` | Match workload packages and images, then NVD or a catalog for CVSS |
| **Exports** | `internal/export/` | SIEM JSONL, Slack webhooks, Jira issues |
| **API** | `internal/api/` | REST + embedded console at `/`; personal token or console session on `/v1` except health |
| **CLI** | `cmd/om/`, `internal/cmd/` | `migrate`, `serve`, `scan`, `rules`, `identity`, `export`, … |
| **Helm** | `deploy/helm/opensourceom/` | API, optional Postgres, optional scheduled collectors |

## Graph schema (v0)

**Node types:** `Internet`, `Network`, `Workload`, `Identity`, `Datastore` (object storage and managed databases), `Finding`, `Control`

**Edge types:** `REACHABLE`, `ASSUMES`, `CAN_ACCESS`, `AFFECTS`, `VIOLATES`

Findings link to affected resources via `VIOLATES` edges. CSPM and CVE findings share the same `Finding` node type but use `finding_type` and `rule_id` / `cve_id` properties for provenance.

See [ADR 001](./adr/001-graph-schema-v0.md), [ADR 002](./adr/002-phase1-findings-ui.md), [ADR 003](./adr/003-phase2-cspm-rbac.md), [ADR 004](./adr/004-collector-plugin-sdk.md), [ADR 005](./adr/005-console-admins.md), [ADR 006](./adr/006-aws-root-volume-packages.md), and [ADR 007](./adr/007-azure-gce-root-volume-packages.md).

## Technology choices

| Layer | Choice | Status |
|-------|--------|--------|
| Collectors | Go (AWS/Azure/GCP/K8s SDKs) plus out-of-process plugins | Shipped |
| Graph store | PostgreSQL | Shipped |
| CSPM rules | Go rule engine + graph context | Shipped |
| API | REST (`net/http`) + personal tokens and Google/GitHub console login | Shipped |
| UI | Embedded static HTML/JS (vis-network) | Shipped |
| Exports | Webhooks + JSONL + Jira REST | Shipped |
| Prod deployment | Kubernetes Helm chart | Shipped |

## Deployment

- **Dev:** Docker Compose — Postgres + API (`docker compose up -d`). `om serve` applies pending migrations before it listens. The CLI can also target Postgres directly; `om migrate` is the schema step when the API is not running.
- **Prod:** Helm chart in `deploy/helm/opensourceom/` (API, optional Postgres, optional scheduled collectors). An init container runs `om migrate`, then the main container runs `om serve`, which applies any still-pending files unless `OM_AUTO_MIGRATE=false`.

## Phase 3

Shipped, in this order:

- Self-hosted operability (console). Read routes require a personal admin token, and the Helm chart schedules collectors when credentials are set.
- CVE enrichment tied to workload inventory. `om enrich cve` writes a finding only when a workload package or image matches.
- Crown-jewel mark on datastores. A tag or label named `sensitivity` or `data-class` is stored on the datastore, and `internet-to-sensitive-datastore` keeps only those paths.
- Attack path as the finding. A rules run writes one `attack_path` finding per existing finding on an internet-reachable workload that can reach a datastore, and stores the path as ordered node ids.
- Cloud audit logs as graph context. `om scan aws` stores CloudTrail management events from the last 24 hours, `om scan azure` stores administrative Activity Log events from the same window, and `om scan gcp` stores Admin Activity audit logs from the same window, on the identity and resource they name when that resource is on an exposed path. `GET /v1/graph/query` returns those events in `audits` for each path that contains the resource. Entra ID sign-in logs, S3 data events such as `GetObject`, and GCP Data Access logs are not collected.

Further community rule packs (PCI and additional CIS mappings) stay open for contributors ([#10](https://github.com/OpenSourceOM/core/issues/10)).

## Phase 4 and Phase 5

Phase 4 writes `packages` (CPE 2.3 names and package URLs) from persistent workload storage onto the workload node that enrichment already matches. The sources, in order, are AWS Linux root volumes, Azure VM and GCE root volumes, boot images, container image layers and function bundles, and shared filesystems (EFS, Azure Files, Filestore). The scan is opt-in. `om scan aws`, `om scan azure`, and `om scan gcp` stay read-only API collectors.

`om scan workload` is the AWS root-volume scan. `om scan workload azure` and `om scan workload gcp` are the same walk for Azure OS disks and GCE boot disks. Each runs as root on a worker in that account and region, snapshots the root disk, mounts the copy read-only, and stores package identifiers only. A later API scan keeps `packages`. Windows, LVM, and non-root disks are skipped. Boot images, container layers, function bundles, and shared filesystems are still open. See [ADR 006](./adr/006-aws-root-volume-packages.md) and [ADR 007](./adr/007-azure-gce-root-volume-packages.md).

Phase 5 adds a finding for a secret pattern or a malware signature on storage that Phase 4 reader already opened. The finding stores the kind and the path. Object bodies and database rows are in neither phase.

Issue links: [ROADMAP.md](./ROADMAP.md) ([#102](https://github.com/OpenSourceOM/core/issues/102) through [#108](https://github.com/OpenSourceOM/core/issues/108)).

See the [website architecture page](https://opensourceom.org/docs/architecture/) for user-facing documentation.
