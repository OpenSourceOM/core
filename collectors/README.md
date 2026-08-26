<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Collectors

Cloud and platform ingestion plugins. Each collector normalizes provider APIs into the OpenSourceOM graph schema.

## Collectors

| Collector | Provider | Status | CLI |
|-----------|----------|--------|-----|
| `demo` | Sample graph | Available | `om scan demo` |
| `aws` | Amazon Web Services | Available | `om scan aws` |
| `azure` | Microsoft Azure | Available | `om scan azure` |
| `gcp` | Google Cloud Platform | Available | `om scan gcp` |
| `kubernetes` | K8s API | Available | `om scan k8s` |

The **demo** collector loads a fixed environment (internet-exposed web tier, production database, public/private buckets, admin vs app identities, public Kubernetes service). Use it to exercise CSPM packs without cloud credentials.

## Interface

Each live collector:

1. **Discover** — list resources and relationships
2. **Emit** — upsert normalized nodes/edges into the graph store

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the graph schema.
