<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 008: Boot-image package inventory

**Status:** Accepted  
**Date:** 2026-10-26  
**Phase:** 4

## Context

[ADR 006](./006-aws-root-volume-packages.md) and [ADR 007](./007-azure-gce-root-volume-packages.md) read each instance's root disk. Many instances boot from one image: an AMI, an Azure image, or a GCE image. That image is where the golden software lives. Scanning only running instances repeats the walk per instance and misses an image that is not currently booted.

`om enrich cve` already matches `packages`. It does not need a new identifier shape.

## Decision

`om scan workload image aws`, `om scan workload image azure`, and `om scan workload image gcp` are subcommands of the same opt-in scan. `om scan aws`, `om scan azure`, and `om scan gcp` stay read-only. The root-volume commands stay as they are.

Each command runs as root on a worker in that account and region. It reads a boot image once, through the same package walker as a root volume:

- AWS creates a volume from the AMI's root snapshot. It does not delete that snapshot.
- Azure creates a disk from a managed image, a gallery image, a community gallery image, or a marketplace image id.
- GCE creates a disk from the image.

The copy is attached read-only, walked, and deleted, including when a later step fails. The graph, logs, and exports store package identifiers. They do not store file contents.

The image's identifiers are added to `packages` on every existing workload launched from that image. Identifiers already stored stay. A package that exists only on an instance disk is not written onto the image and is not copied to another instance. `om scan workload aws`, `om scan workload azure`, and `om scan workload gcp` still replace `packages` with the packages on that instance's own disk.

Images the account owns are read even when no instance is running. An image that instances were launched from is read even when another account published it. Marketplace and shared images the account cannot snapshot are skipped, and the command says so. Windows images are skipped. AWS instance-store images are skipped.

The new AWS actions are `ec2:DescribeImages` and the volume create, attach, and delete calls. They do not include `ec2:CreateSnapshot` or `ec2:DeleteSnapshot`. The new Azure actions are `Microsoft.Compute/images/read`, `Microsoft.Compute/galleries/images/versions/read`, and the disk create, delete, and attach calls. The new GCP permissions are `compute.images.list`, `compute.images.useReadOnly`, `compute.disks.list`, and the disk create, delete, and attach calls. The API collectors do not gain these permissions.

Container layers, function bundles, and shared filesystems stay on later Phase 4 issues. Secret and malware findings stay on Phase 5.

## Consequences

Each command has to run on a VM in the account, in the region being scanned. A process killed with SIGKILL can leave a volume or disk; the same `opensourceom:scan=workload` tag or `opensourceom-scan=workload` label from the root-volume scan is how to find it. The Helm chart does not schedule these commands.

`om enrich cve` is unchanged. It attaches a CVE only when one of these identifiers matches. An image with no instance in the graph is still read, and its packages are stored when a later run finds a workload launched from it.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [ADR 006](./006-aws-root-volume-packages.md)
- [ADR 007](./007-azure-gce-root-volume-packages.md)
- [Issue #104](https://github.com/OpenSourceOM/core/issues/104)
