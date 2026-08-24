<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 001: Graph Schema v0

**Status:** Accepted  
**Date:** 2026-08-24  
**Phase:** 0

## Context

OpenSourceOM needs a minimal graph model to connect cloud inventory (workloads, identities, data stores, network controls) with attack-path queries. Phase 0 targets a walking skeleton: ingest from AWS, store in Postgres, and run a handful of named path queries from the CLI and HTTP API.

## Decision

### Storage

- **Backend:** PostgreSQL with two tables — `nodes` and `edges`.
- **Migrations:** Versioned SQL files in `migrations/`, applied by `om migrate`.
- **Properties:** Flexible `JSONB` column on nodes and edges for provider-specific attributes.

### Node types (v0)

| Type | Purpose | AWS examples |
|------|---------|--------------|
| `Internet` | Synthetic entry point for external reachability | `internet:global` |
| `Network` | Network controls (security groups, firewalls) | EC2 security groups |
| `Workload` | Compute resources | EC2 instances |
| `Identity` | Principals that can assume access | IAM roles |
| `Datastore` | Storage with sensitivity context | S3 buckets |
| `Finding` | *(reserved)* Security findings linked to graph nodes | — |
| `Control` | *(reserved)* Policy/guardrail nodes | — |

### Edge types (v0)

| Type | Meaning |
|------|---------|
| `REACHABLE` | Source can reach target (e.g. Internet → workload) |
| `ASSUMES` | Identity assumption chain |
| `CAN_ACCESS` | Identity or workload can access a resource |
| `AFFECTS` | Workload attached to or governed by a network control |
| `VIOLATES` | Finding violates a control *(reserved)* |

### Node ID format

Provider-scoped IDs: `aws:{account_id}:{region}:{kind}:{resource_id}`

Synthetic nodes use stable global IDs (e.g. `internet:global`).

### Named queries (v0)

| Query | Description |
|-------|-------------|
| `internet-to-workload` | Paths from Internet to reachable workloads |
| `public-s3-buckets` | S3 buckets with public exposure indicators |
| `admin-identities` | IAM roles with broad admin indicators |
| `toxic-s3-public-with-admin-role` | Public S3 buckets linked to admin-capable identities |

## Consequences

- **Simple to operate:** Single Postgres instance, no graph DB dependency in Phase 0.
- **Extensible:** New node/edge types and properties can be added without breaking existing rows.
- **Limitations:** Recursive path queries are SQL-based and capped (depth 6); not suitable for very large graphs without indexing and query optimization in later phases.
- **Heuristics:** Phase 0 AWS collector uses heuristics (e.g. admin role name matching, admin→public S3 edges) that will be replaced with policy-aware analysis in Phase 1+.

## References

- [docs/ARCHITECTURE.md](../ARCHITECTURE.md)
- [migrations/001_graph_schema.sql](../../migrations/001_graph_schema.sql)
