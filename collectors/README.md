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

The **AWS** collector emits properties the CIS pack matches on: `open_ingress`, `imdsv2`, `public_ip`, S3 `encryption` / `versioning` / `public_access_block`, and IAM user `mfa` / `unused_access_keys`. It also records RDS and Aurora instances as datastores. S3 bucket tags and the RDS `TagList` copy `sensitivity` or `data-class` onto the datastore. `sensitivity` wins when both are set. The same scan reads CloudTrail management events from the last 24 hours and stores the ones that name an identity and a resource on an exposed path. A failed lookup omits those events.

The **Azure** collector records logical SQL servers. The same scan reads administrative Activity Log events from the last 24 hours and stores the ones that name an identity and a resource on an exposed path. A failed lookup omits those events. Entra ID sign-in logs are not part of this scan. The **GCP** collector records Cloud SQL instances. A workload gets `CAN_ACCESS` only when a security group, firewall, or VPC path allows it. Azure copies the crown-jewel mark from storage-account and SQL-server tags. GCP copies it from a bucket label or a Cloud SQL user label. The keys are `sensitivity` and `data-class`. A plugin may set `sensitivity` on a datastore directly.

The **Kubernetes** collector records Ingress objects and whether a NetworkPolicy selects each pod. A pod is internet-reachable from a LoadBalancer or an Ingress backend unless that policy governs ingress and does not allow the world. NodePort alone is not exposure.

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
