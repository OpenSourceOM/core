<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Collectors

Cloud and platform ingestion plugins. Each collector normalizes provider APIs into the OpenSourceOM graph schema.

## Planned collectors

| Collector | Provider | Status |
|-----------|----------|--------|
| `aws` | Amazon Web Services | Planned |
| `azure` | Microsoft Azure | Planned |
| `gcp` | Google Cloud Platform | Planned |
| `kubernetes` | K8s API | Planned |

## Interface (draft)

Each collector implements:

1. **Discover** — list resources and relationships
2. **Sync** — incremental updates since last run
3. **Emit** — push normalized nodes/edges to the ingestion API

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the graph schema.
