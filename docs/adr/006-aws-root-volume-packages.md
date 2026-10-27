<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 006: AWS Linux root-volume package inventory

**Status:** Accepted  
**Date:** 2026-10-14  
**Phase:** 4

## Context

`om enrich cve` writes a finding when `packages` on a workload matches a CPE 2.3 name or a versioned package URL. `om scan aws` records the instance from `DescribeInstances` and copies the AMI id into `image`. It does not read the root volume, so a package installed on the instance never reaches `packages`.

Reading a volume means creating a snapshot and attaching a copy. That is a write to the account. The API collectors stay read-only.

## Decision

`om scan workload aws` is a separate command. It runs as root on an EC2 instance in the account and region being scanned.

For each Linux instance with an EBS root volume, the command:

1. Creates a snapshot of the root volume and a volume from that snapshot in the worker's availability zone.
2. Attaches the volume to the worker and mounts it read-only.
3. Reads the dpkg, apk, or rpm database and writes CPE 2.3 names and versioned package URLs onto `packages` of the existing workload node.
4. Unmounts, detaches, and deletes the volume and the snapshot, including when a later step fails.

Windows instances, instance-store roots, LVM physical volumes, and non-root disks are skipped. The graph, logs, and exports store package identifiers. They do not store file contents.

An inventory upsert that omits `packages` keeps the list already stored. `om scan aws` can run again without erasing the workload scan. An upsert that sets `packages`, including an empty list, replaces it.

The IAM actions are `ec2:CreateSnapshot`, `ec2:AttachVolume`, `ec2:DeleteSnapshot`, `ec2:DeleteVolume`, the describe and tag calls around that lifecycle, and `kms:CreateGrant` plus `kms:Decrypt` (with `kms:DescribeKey`, `kms:GenerateDataKeyWithoutPlaintext`, and `kms:ReEncrypt*`) for an encrypted root volume. `om scan aws` does not gain these actions.

Azure, GCE, boot images, container layers, function bundles, and shared filesystems stay on later Phase 4 issues. Secret and malware findings stay on Phase 5, after this reader exists.

## Consequences

The command has to run on an instance in the account. A process killed with SIGKILL can leave a snapshot or volume; both are tagged `opensourceom:scan=workload`. The Helm chart does not schedule this command.

`om enrich cve` is unchanged. It attaches a CVE only when one of these identifiers matches.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [Issue #102](https://github.com/OpenSourceOM/core/issues/102)
