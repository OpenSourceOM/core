<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 010: Console wizard for cloud connect

**Status:** Accepted
**Date:** 2026-11-05
**Phase:** 4

## Context

Connecting an account means granting a read-only inventory role and, separately, the scanner and production roles in [deploy/connect](../../deploy/connect/README.md). Doing that from a list of shell exports is where setup fails. The inventory scan and the package scan are different permissions. The package scan still has to run as root on a worker.

## Decision

Settings → Connect a cloud generates an external id, opens the cloud's own template, and asks for a role ARN, subscription id, or project id. Verify calls the cloud with the server's existing credentials. The inventory scan can run from that screen. The package scan stays a command on the worker.

The screen does not accept an access key, a client secret, or a service-account JSON key. `om connect` prints the same steps. `om scan aws --role-arn` assumes the inventory role when this machine is not already that role.

## Consequences

AWS CloudFormation quick-create links fetch the template from the public repo. The API also serves the file for download. Azure and GCP copy a script into Cloud Shell. A saved connection stores role ARNs and the external id, not a secret.

## References

- [deploy/connect](../../deploy/connect/README.md)
- [ADR 009](./009-scanner-account.md)
