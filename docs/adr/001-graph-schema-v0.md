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
| `Datastore` | Storage and managed databases with sensitivity context | S3 buckets, RDS, Azure SQL, Cloud SQL |
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

Provider-scoped IDs: `aws:{account_id}:{region}:{kind}:{resource_id}` for regional resources (EC2 instances and security groups). IAM principals and S3 buckets are account-global and use `global` in place of the region, so a scan in a second region updates the same nodes.

Synthetic nodes use stable global IDs (e.g. `internet:global`).

### Named queries (v0)

| Query | Description |
|-------|-------------|
| `internet-to-workload` | Paths from Internet to reachable workloads |
| `internet-to-datastore` | Paths from Internet through a workload to a datastore |
| `internet-to-sensitive-datastore` | The same walk, kept only when the datastore `sensitivity` property is a non-empty string |
| `public-datastore` | Datastores with public exposure indicators. `public-s3-buckets` is an alias. |
| `admin-identities` | Identities with broad administrative permissions |
| `admin-to-public-datastore` | Public datastores linked to admin-capable identities. `toxic-s3-public-with-admin-role` is an alias. |

## Consequences

- **Simple to operate:** Single Postgres instance, no graph DB dependency in Phase 0.
- **Extensible:** New node/edge types and properties can be added without breaking existing rows.
- **Limitations:** Recursive path queries are SQL-based and capped (depth 6); not suitable for very large graphs without indexing and query optimization in later phases.
- **Heuristics:** AWS `admin_access` follows attached and inline policies: an allow of `*` on `*`, or the AWS-managed `AdministratorAccess` policy. Deny statements, conditions, permission boundaries, and group policies are not evaluated. Azure `admin_access` is Owner, Contributor, User Access Administrator, or a custom role whose actions are `*` or include `Microsoft.Authorization/roleAssignments/write`. GCP `admin_access` is `roles/owner`, `roles/editor`, `roles/resourcemanager.projectIamAdmin`, or a custom role that includes `resourcemanager.projects.setIamPolicy`. Azure `CAN_ACCESS` for storage follows role-assignment scope. GCP `CAN_ACCESS` for buckets follows project and bucket IAM. Conditional assignments and bindings are not treated as access. Those identity edges do not apply to managed databases. Azure and GCP `REACHABLE` requires an internet path and an allow. A path is a public IP, or a private address behind a load balancer with a public frontend. GCP allow is an ingress firewall rule from `0.0.0.0/0` or `::/0` that selects the instance and is not covered by a higher-priority deny; no matching allow stays closed. Azure allow is an inbound NSG rule from `Internet`, `*`, or `0.0.0.0/0` that is not covered by a higher-priority deny. When both a NIC and a subnet NSG are attached, both must allow. A VM with a public IP and no NSG stays reachable, which is Azure's platform default. Network endpoint groups are not expanded. Kubernetes `REACHABLE` follows a LoadBalancer service or an Ingress backend that selects the pod. NodePort alone does not. A NetworkPolicy that selects the pod and governs ingress removes that edge unless a rule allows every source or `0.0.0.0/0` / `::/0`. Gateway API and internal-only ingress classes are not modeled.
- **Crown jewels:** A datastore may carry `sensitivity`. Collectors copy it from a resource tag or label named `sensitivity` or `data-class` when the provider returns one. `sensitivity` wins when both are present. A blank value is omitted. Plugins may set the property on the node. Object contents are not read. `internet-to-datastore` stays unfiltered. `internet-to-sensitive-datastore` is that walk restricted to datastores whose `sensitivity` is a non-empty string.
- **Managed databases:** RDS (including Aurora instances), Azure SQL servers, and Cloud SQL instances are `Datastore` nodes. `public_access` is true only when the endpoint is open to the internet: RDS is publicly accessible and a security group allows the instance port from `0.0.0.0/0` or `::/0`; an Azure SQL server has public network access and a firewall rule from `0.0.0.0` to `255.255.255.255`; Cloud SQL has a public IPv4 address and an authorized network of `0.0.0.0/0` or `::/0`. Workload `CAN_ACCESS` follows that network path. RDS requires the same VPC and a security group that references the workload or contains its private IPv4 address on the instance port. Azure SQL requires a virtual-network rule for the VM's subnet, or a firewall range that contains the VM's public IP while the public endpoint is enabled. Cloud SQL requires the instance's private-IP network, or an authorized network that contains the instance's public IP. Same-account membership is not enough. VPC peering, prefix lists, Azure private endpoints, default outbound SNAT, and Cloud SQL Private Service Connect are not expanded.

## References

- [docs/ARCHITECTURE.md](../ARCHITECTURE.md)
- [migrations/001_graph_schema.sql](../../migrations/001_graph_schema.sql)
