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

## Phase 3 — Ecosystem

Phase 3 is complete.

- [x] Plugin SDK for custom collectors (`sdk/collector`, `om scan plugin`)
- [x] Helm chart for production Kubernetes
- [x] Community rule packs (CIS AWS–inspired YAML pack + embed loader)
- [x] Sample environment (`om scan demo`)

Phases 0–2 shipped the walking skeleton. Exposure and identity edges now follow the cloud and Kubernetes. CVE findings follow package and image inventory on the workload. Datastores carry a sensitivity mark when a tag or label names one. A rules run writes an attack-path finding for each finding already on an internet-reachable workload that can reach a datastore. `om scan aws` attaches recent CloudTrail management events, `om scan azure` attaches recent Activity Log events, and `om scan gcp` attaches recent Admin Activity audit logs, to the identity and resource they name. Path queries return an event when that resource is on the path.

Correctness and operability come first:

- **Self-hosted operability** — read APIs require a personal admin token ([#22](https://github.com/OpenSourceOM/core/issues/22)). The Helm chart schedules collectors when credentials are set ([#32](https://github.com/OpenSourceOM/core/issues/32)).

The path, in order:

- [x] **CVE enrichment tied to workload inventory** — [#12](https://github.com/OpenSourceOM/core/issues/12)
- [x] **Crown-jewel mark on datastores** — [#58](https://github.com/OpenSourceOM/core/issues/58)
- [x] **Attack path as the finding** — [#57](https://github.com/OpenSourceOM/core/issues/57)
- [x] **Cloud audit logs as graph context** — [#33](https://github.com/OpenSourceOM/core/issues/33) (AWS CloudTrail and Azure Activity Log)
- [x] **GCP Cloud Audit Logs as graph context** — [#74](https://github.com/OpenSourceOM/core/issues/74)

`om scan aws` reads CloudTrail management events from the last 24 hours. `om scan azure` reads administrative Activity Log events over the same window. `om scan gcp` reads Admin Activity audit logs over the same window. An event is stored on the identity and the resource it names when that resource sits on an exposed path. Named path queries list those events when the resource is on the returned path. Data Access logs, Entra ID sign-in logs, and S3 object data events such as `GetObject` stay out.

The ordered path above is complete.

## Phase 4 — Workload inventory

Phase 4 is open. Cloud collectors record the VM, its exposure, and its identity. They do not record the packages installed on it. `om enrich cve` already writes a finding when `packages` on a workload matches. This phase fills that property from persistent workload storage.

The phase ends when a package found in that storage is a CVE finding on the workload the graph already stores. A block volume is the first source. Boot images, container image layers, function bundles, and shared filesystems are the rest.

The scan is opt-in and separate from `om scan aws`, `om scan azure`, and `om scan gcp`. Those commands stay read-only. The workload scan runs a worker in the account and region, reads package metadata, and writes CPE 2.3 names and package URLs onto the existing workload. Snapshots and mounts are removed when the scan finishes, including when it fails. File contents stay on the storage.

The path, in order:

- [x] **AWS Linux root volumes** — [#102](https://github.com/OpenSourceOM/core/issues/102)
- [x] **Azure VM and GCE root volumes** — the same walker, those snapshot APIs — [#103](https://github.com/OpenSourceOM/core/issues/103)
- [ ] **Boot images** — an AMI and the Azure and GCE equivalents, scanned once and applied to instances launched from that image — [#104](https://github.com/OpenSourceOM/core/issues/104)
- [ ] **Container image layers and function bundles** — layers for images already stored on Kubernetes workloads, plus Lambda deployment packages and the Azure and GCP equivalents. No volume attach — [#105](https://github.com/OpenSourceOM/core/issues/105)
- [ ] **Shared filesystems** — EFS, Azure Files, and Filestore, when the application is installed there and a root-volume scan would miss it — [#106](https://github.com/OpenSourceOM/core/issues/106)

`om scan workload` reads Linux root volumes in the current AWS account. It runs as root on an EC2 instance in that account, snapshots the root volume, mounts the copy read-only, and writes CPE 2.3 names and package URLs onto `packages`. `om scan workload azure` does the same for managed OS disks from an Azure VM in that region, and `om scan workload gcp` does it for GCE boot disks from an instance in that region. A later `om scan aws`, `om scan azure`, or `om scan gcp` leaves `packages` in place. Windows, LVM, and disks other than the root volume are skipped.

Object bodies and database rows stay out. They are customer data, not the installed software. A public bucket or database is already an exposure finding from the API scan.

## Phase 5 — Findings on inventoried storage

Phase 5 starts after a Phase 4 reader has opened that storage. A secret pattern or a malware signature found there becomes a finding on the same workload. The graph stores the kind and the path. It does not store the secret or the file. The finding then ranks with the other findings on an internet-reachable workload.

The path, in order:

- [ ] **Secrets** — kind and path only — [#107](https://github.com/OpenSourceOM/core/issues/107)
- [ ] **Malware** — signature name and path only — [#108](https://github.com/OpenSourceOM/core/issues/108)

Object bodies and database rows stay out of this phase as well.

## Alongside the phases

[#10](https://github.com/OpenSourceOM/core/issues/10) stays open for a contributor who wants another rule pack (PCI and additional CIS mappings). It does not reopen Phase 3, and it is not Phase 4 or Phase 5.

## Open source vs. commercial

The free OSS core focuses on **defending against external attackers** — understanding what is exposed, what paths exist from the internet to sensitive assets, and which findings matter because an outsider could reach them.

| Open source (OSS) | Commercial (planned) |
|-------------------|----------------------|
| Attack path queries (internet → workload → datastore) | Insider / internal-threat analysis |
| Graph-context CSPM and CVE prioritization | Privileged access governance and blast-radius controls for operators |
| Multi-cloud + Kubernetes inventory | Multi-tenant RBAC, org/account scoping |
| Self-hosted API, CLI, and web console | SAML and custom enterprise identity providers |
| Console admins via Google or GitHub login | Viewer and other non-admin roles |
| Community collectors and rule packs | Enterprise compliance workflows |
| Cloud audit ingest as graph context | Immutable platform audit logs (who used OpenSourceOM) |
| Workload package inventory (Phase 4) and secret or malware findings on that storage (Phase 5) | Classification of object bodies and database rows |

Console login in the OSS core is email and password. Google and GitHub are optional. The first account is created from the setup form or `om admin create`, and later admins get a temporary password. Every signed-in account is an admin. A personal API token for scripts is created only when that admin asks for one. Bring-your-own identity providers stay commercial.

Cloud provider audit APIs (for example CloudTrail) are Phase 3 graph context ([#33](https://github.com/OpenSourceOM/core/issues/33)): evidence of exposure and attack paths. **Platform audit logs** — operator actions in the console/API, SSO identity, retention, and auditor export — belong in the commercial offering.

Phase 4 and Phase 5 stay in the open-source core: which packages, secrets, and malware sit on storage an outsider can reach. Classification of object bodies and database rows belongs with the commercial offering.

This split keeps the OSS project useful for any team that needs graph-native **external** risk prioritization, while commercial offerings can address **internal** risk and enterprise deployment needs without bloating the core repo.

## How to influence the roadmap

Comment on an [open issue](https://github.com/OpenSourceOM/core/issues), or open a [GitHub Discussion](https://github.com/OpenSourceOM/core/discussions) with the `roadmap` label when the change is not tracked yet. We prioritize features that improve **graph accuracy**, **prioritization quality**, and **self-hosted operability**.
