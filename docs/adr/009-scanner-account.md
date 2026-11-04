<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 009: Scanner account for workload disks

**Status:** Accepted  
**Date:** 2026-10-27  
**Phase:** 4

## Context

[ADR 006](./006-aws-root-volume-packages.md), [ADR 007](./007-azure-gce-root-volume-packages.md), and [ADR 008](./008-boot-image-packages.md) mount a copy of a root volume or boot image on a worker in the account being scanned. That worker is compute inside the production account. A role can create a snapshot from anywhere. Attaching the disk still needs a machine, and that machine does not have to live in the account that owns the volume.

## Decision

The worker runs in a scanner account, subscription, or project. The account being scanned grants a role that can describe instances, create a snapshot, share it with the scanner, and delete snapshots this scan tagged. It does not grant attach, and it does not start an instance.

`om scan workload aws` runs as root on an EC2 instance in the scanner account. It assumes the production role with an external id, creates the snapshot, and shares it. The worker copies the snapshot into the scanner account, encrypts the copy with a key in that account when one is set, attaches the copy, and reads package databases. It then deletes the copy and the source snapshot. An encrypted source requires `--kms-key`. The AMI scan shares the existing snapshot, copies it, and does not delete the AMI snapshot.

`om scan workload azure` and `om scan workload gcp` use one credential that holds the production role and the scanner role. `AZURE_SUBSCRIPTION_ID` and `GCP_PROJECT_ID` are the production ids. Snapshots are created there. Disks are created and attached in the worker's subscription or project. Azure snapshots go in the `opensourceom-snapshots` resource group. The same split applies to boot images: the image stays in the production account, and the disk is created next to the worker.

`deploy/connect` is the customer-facing grant. Terraform and OpenTofu share one module per side. AWS also has CloudFormation and a shell script. Azure has an `az` script. GCP has a `gcloud` script. A test checks those files against `Permissions` and `WorkerPermissions`. The API collectors stay read-only. The Helm chart still does not schedule the workload scan, because the worker is a VM in the scanner account.

The graph stores package identifiers for the production account. File contents are not stored. Blocks are read in the scanner account and discarded after the package walk.

## Consequences

Each production account owner applies the production stack and adds the scanner principal to every customer-managed key that encrypts a root volume. The worker is tagged so a killed process can be cleaned up: `opensourceom:scan=workload` on snapshots and volumes, and `opensourceom-scan=workload` on GCP. A snapshot shared with the scanner account is unshared when the copy is deleted. Same-subscription and same-project runs still mount in that subscription or project; the AWS command refuses a snapshot role that lives in the scanner account.

## References

- [deploy/connect](../../deploy/connect/README.md)
- [ADR 006](./006-aws-root-volume-packages.md)
- [ADR 007](./007-azure-gce-root-volume-packages.md)
- [ADR 008](./008-boot-image-packages.md)
