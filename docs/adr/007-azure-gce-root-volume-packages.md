<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 007: Azure and GCE root-volume package inventory

**Status:** Accepted  
**Date:** 2026-10-15  
**Phase:** 4

## Context

[ADR 006](./006-aws-root-volume-packages.md) defined `packages` and `om scan workload aws` for AWS Linux root volumes. `om scan azure` and `om scan gcp` still record the virtual machine from the cloud API and do not read the OS disk, so a package installed on an Azure VM or a GCE instance never reaches `packages`.

The filesystem walk is the same. The snapshot and attach APIs are not.

## Decision

`om scan workload aws`, `om scan workload azure`, and `om scan workload gcp` are subcommands of the same opt-in scan. `om scan azure` and `om scan gcp` stay read-only.

`om scan workload azure` runs as root on an Azure VM in the subscription. For each Linux VM in that region with a managed OS disk, it creates a snapshot and a disk in the worker's resource group and zone, attaches the disk to the worker, and mounts it read-only. `om scan workload gcp` runs as root on a GCE instance in the project. For each Linux instance in that region with a persistent boot disk, it creates a snapshot, creates a disk in the worker's zone, and attaches that disk read-only.

Both commands then run the package walk from ADR 006 and write CPE 2.3 names and versioned package URLs onto the workload node `om scan azure` or `om scan gcp` already stored. They delete the snapshot and the disk, including when a later step fails. The graph, logs, and exports store package identifiers. They do not store file contents.

Windows, ephemeral Azure OS disks, unmanaged VHDs, GCE local SSD boot disks, customer-supplied encryption keys, LVM physical volumes, and data disks are skipped. A customer-managed key is not copied into the graph. The identity needs the unwrap permission listed below, and the snapshot keeps the source disk's key.

Azure copies are tagged `opensourceom:scan=workload` and are created with public network access disabled. GCE label keys cannot contain a colon, so those copies are labeled `opensourceom-scan=workload`.

The Azure actions are `Microsoft.Compute/snapshots/write`, `Microsoft.Compute/snapshots/delete`, `Microsoft.Compute/disks/write`, `Microsoft.Compute/disks/delete`, `Microsoft.Compute/virtualMachines/attachDetachDataDisks/action`, and `Microsoft.KeyVault/vaults/keys/unwrap/action` (with `keys/wrap/action` when the snapshot keeps the key). The GCP permissions are `compute.disks.createSnapshot`, `compute.snapshots.delete`, `compute.disks.create`, `compute.disks.delete`, `compute.instances.attachDisk`, `compute.instances.detachDisk`, and `cloudkms.cryptoKeyVersions.useToDecrypt` (with `useToEncrypt`). The API collectors do not gain these permissions.

Boot images, container layers, function bundles, and shared filesystems stay on later Phase 4 issues. Secret and malware findings stay on Phase 5.

## Consequences

Each command has to run on a VM in the subscription or project, in the region being scanned. A process killed with SIGKILL can leave a snapshot or disk; the tag or label above is how to find it. The Helm chart does not schedule these commands.

`om enrich cve` is unchanged. It attaches a CVE only when one of these identifiers matches. The Azure graph id is still `azure:<subscription>:<AZURE_LOCATION>:workload:<vm name>`, which is the name alone. Two virtual machines with the same name in different resource groups already share that id.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [ADR 006](./006-aws-root-volume-packages.md)
- [Issue #103](https://github.com/OpenSourceOM/core/issues/103)
