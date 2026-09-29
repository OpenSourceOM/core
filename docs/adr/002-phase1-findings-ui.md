<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 002: Phase 1 — Findings, Enrichment, and Web Console

**Status:** Accepted  
**Date:** 2026-08-24  
**Phase:** 1

## Context

Phase 0 delivered ingest, storage, and basic path queries. Phase 1 needs prioritization signals (CVE severity), a user-facing console, multi-cloud collectors, and the flagship query: paths from the internet through workloads to datastores.

## Decision

### Attack paths

- Add named query `internet-to-datastore` requiring at least one `Workload` node on the path.
- Link internet-facing workloads to public datastores via `CAN_ACCESS` edges (heuristic, same account).

### CVE enrichment

- `om enrich cve` creates `Finding` nodes with normalized severity (critical/high/medium/low/info).
- CVSS scores fetched from the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities); optional `NVD_API_KEY` for rate limits.
- Findings link to workloads via `VIOLATES` edges.
- Auto-creates an "Internet-exposed workload" finding for reachable workloads with public IPs.

### Web UI

- Embedded static console served by the API at `/`.
- Graph explorer (vis-network) with full snapshot or path-query overlay.
- Findings sidebar sorted by normalized severity.

### Multi-cloud collectors

| Provider | Resources | CLI |
|----------|-----------|-----|
| Azure | VMs, storage accounts, Azure SQL servers, subscription RBAC | `om scan azure` |
| GCP | GCE instances, GCS buckets, Cloud SQL, service accounts | `om scan gcp` |

Auth uses each cloud's default credential chain (`DefaultAzureCredential`, GCP ADC).

## Consequences

- Heuristic edges and default Log4Shell CVE for demo enrichment were placeholders. Azure and GCP `CAN_ACCESS` for object storage now follow role-assignment scope and IAM bindings; the same-account link from every internet-facing workload to every public datastore has been removed. Managed-database `CAN_ACCESS` follows the network path described in [ADR 001](./001-graph-schema-v0.md). `REACHABLE` for those clouds requires an internet path and a firewall or NSG allow, including a private instance behind a public load balancer. The Log4Shell default remains a placeholder.
- Azure VM public IP detection follows the NIC to the address. A public IP with no NSG is reachable. A public IP whose NSG or subnet NSG does not allow the internet is not. GCP sets `REACHABLE` only when a public address or external load balancer is also allowed by a firewall rule.
- UI is static HTML/JS embedded in Go — a dedicated frontend package may split out later.

## References

- [docs/adr/001-graph-schema-v0.md](./001-graph-schema-v0.md)
- [internal/enrichment/](../internal/enrichment/)
- [internal/api/web/](../internal/api/web/)
