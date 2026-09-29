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
| external plugin | Any executable using `sdk/collector` | Available | `om scan plugin` |

The **demo** collector loads a fixed environment (internet-exposed web tier, production database, public/private buckets, admin vs app identities, public Kubernetes service). Use it to exercise CSPM packs without cloud credentials.

The **AWS** collector emits properties the CIS pack matches on: `open_ingress`, `imdsv2`, `public_ip`, S3 `encryption` / `versioning` / `public_access_block`, and IAM user `mfa` / `unused_access_keys`.

## Interface

Each built-in collector:

1. **Discover** — list resources and relationships
2. **Emit** — replace that account's inventory in the graph store (nodes and edges absent from the new batch are deleted)

## External plugins

`om scan plugin` runs an executable and replaces inventory for each account in the graph batch it writes to stdout. Go plugins import `github.com/OpenSourceOM/core/sdk/collector`, implement `Collector`, and call `collector.Run` from `main`. Other languages emit the same JSON (`nodes` and `edges`, schema v0). See [ADR 004](../docs/adr/004-collector-plugin-sdk.md) and [examples/collector](../examples/collector).

```bash
go build -o example-collector ./examples/collector
./om scan plugin -- ./example-collector
```

Plugins inherit the environment of `om` and must stay read-only toward the systems they inventory.

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the graph schema.
