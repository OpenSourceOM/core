<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Roadmap

High-level plan for OpenSourceOM core. Timelines are approximate and community-driven.

## Phase 0 — Foundation

- [x] Public org, website, and repo scaffolding
- [x] Graph schema v0 (nodes: workload, identity, datastore, finding, network)
- [x] AWS collector prototype (EC2, IAM, S3, security groups)
- [x] Docker Compose dev stack (Postgres + API)
- [x] Basic API: ingest + graph stats + named path queries
- [x] `om` CLI: migrate, serve, scan, graph stats, paths run

## Phase 1 — Minimum viable graph

- [x] Attack path query: internet → workload → datastore
- [x] CVE enrichment and severity normalization
- [x] Simple web UI: graph explorer + finding list
- [x] Azure collector (VM, RBAC, Storage)
- [x] GCP collector (GCE, IAM, GCS)

## Phase 2 — CNAPP parity (core features)

- [x] CSPM rules engine with graph context
- [x] Identity blast radius reports
- [x] Kubernetes inventory connector
- [x] SIEM / Jira / Slack export

## Phase 3 — Ecosystem *(current)*

- [x] Plugin SDK for custom collectors (`sdk/collector`, `om scan plugin`)
- [x] Helm chart for production Kubernetes
- [x] Community rule packs (CIS AWS–inspired YAML pack + embed loader)
- [x] Sample environment (`om scan demo`)
- [ ] Broader community rule packs (PCI and additional CIS mappings) — [#10](https://github.com/OpenSourceOM/core/issues/10)

Phases 0–2 shipped the walking skeleton. Exposure and identity edges now follow the cloud and Kubernetes. CVE findings follow package and image inventory on the workload. Datastores carry a sensitivity mark when a tag or label names one. Current work is the attack path as the thing an operator fixes.

Correctness and operability come first:

- **Self-hosted operability** — read APIs honor `OM_API_SECRET` ([#22](https://github.com/OpenSourceOM/core/issues/22)). The Helm chart schedules collectors when credentials are set ([#32](https://github.com/OpenSourceOM/core/issues/32)).

The path, in order:

- [x] **CVE enrichment tied to workload inventory** — [#12](https://github.com/OpenSourceOM/core/issues/12)
- [x] **Crown-jewel mark on datastores** — [#58](https://github.com/OpenSourceOM/core/issues/58)
- **Attack path as the finding** — [#57](https://github.com/OpenSourceOM/core/issues/57)
- **Cloud audit logs as graph context** — [#33](https://github.com/OpenSourceOM/core/issues/33), after those edges are trustworthy

[#10](https://github.com/OpenSourceOM/core/issues/10) stays open for a contributor who wants another rule pack. The priority above is graph accuracy.

## Open source vs. commercial

The free OSS core focuses on **defending against external attackers** — understanding what is exposed, what paths exist from the internet to sensitive assets, and which findings matter because an outsider could reach them.

| Open source (OSS) | Commercial (planned) |
|-------------------|----------------------|
| Attack path queries (internet → workload → datastore) | Insider / internal-threat analysis |
| Graph-context CSPM and CVE prioritization | Privileged access governance and blast-radius controls for operators |
| Multi-cloud + Kubernetes inventory | Multi-tenant RBAC, org/account scoping |
| Self-hosted API, CLI, and web console | SAML / SSO and enterprise identity integrations |
| Community collectors and rule packs | Enterprise compliance workflows |
| Cloud audit ingest as graph context | Immutable platform audit logs (who used OpenSourceOM) |

Cloud provider audit APIs (for example CloudTrail) are Phase 3 graph context ([#33](https://github.com/OpenSourceOM/core/issues/33)): evidence of exposure and attack paths. **Platform audit logs** — operator actions in the console/API, SSO identity, retention, and auditor export — belong in the commercial offering.

This split keeps the OSS project useful for any team that needs graph-native **external** risk prioritization, while commercial offerings can address **internal** risk and enterprise deployment needs without bloating the core repo.

## How to influence the roadmap

Comment on an [open issue](https://github.com/OpenSourceOM/core/issues), or open a [GitHub Discussion](https://github.com/OpenSourceOM/core/discussions) with the `roadmap` label when the change is not tracked yet. We prioritize features that improve **graph accuracy**, **prioritization quality**, and **self-hosted operability**.
