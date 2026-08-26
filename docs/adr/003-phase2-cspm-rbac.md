<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 003: Phase 2 — CSPM Rules, Blast Radius, K8s, Exports

**Status:** Accepted  
**Date:** 2026-08-24  
**Phase:** 2

## Context

Phase 1 delivered multi-cloud ingest, CVE enrichment, and a web console. Phase 2 adds CNAPP-style capabilities: policy findings with graph context, identity blast radius, Kubernetes inventory, and outbound integrations.

Multi-tenant RBAC (admin/viewer roles, account scoping) was considered for Phase 2 but **deferred** per the [OSS vs. commercial split](../ROADMAP.md#open-source-vs-commercial): the free core targets external-attack defense; internal-threat controls and enterprise auth (SAML, RBAC) belong outside OSS.

## Decision

### CSPM rules engine

- Built-in rules in Go (`internal/rules/`) evaluate the graph and emit `Finding` nodes with `finding_type=cspm`.
- Rules attach **graph context** (internet reachability, path-to-datastore, admin access) to boost normalized severity scores.
- CLI: `om rules list`, `om rules run [rule-id]`; API: `GET /v1/rules`, `POST /v1/rules/run`.

### Identity blast radius

- Recursive traversal over `CAN_ACCESS` and `ASSUMES` edges from an identity node.
- CLI: `om identity blast-radius --name ROLE`; API: `GET /v1/identity/blast-radius`.

### Kubernetes collector

- `om scan k8s` uses in-cluster or kubeconfig credentials.
- Maps pods → `Workload`, namespaces/services → `Network`, service accounts → `Identity`.

### Exports

- `om export findings run --format siem|slack|jira`
- SIEM export emits JSON Lines; Slack/Jira use webhooks/API tokens from environment variables.

### API authentication (OSS)

- Write endpoints (`POST /v1/ingest`, `POST /v1/rules/run`, `POST /v1/export/slack`) require `OM_API_SECRET` via `Authorization: Bearer` or `X-API-Key`.
- Read endpoints are open when no secret is configured (local dev); production should always set `OM_API_SECRET`.

## Consequences

- CSPM rules are code-defined in Phase 2; YAML rule packs (`packs/*.yaml`) land in Phase 3 and are embedded at compile time.
- K8s public exposure uses heuristics (LoadBalancer services, ingress labels) — not a full network policy model yet.
- Role-based access, multi-tenant scoping, and SAML/SSO are out of scope for the OSS core — see [OSS vs. commercial](./ROADMAP.md#open-source-vs-commercial).

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [internal/rules/](../../internal/rules/)
