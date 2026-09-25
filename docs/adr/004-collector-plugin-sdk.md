<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# ADR 004: Collector plugin SDK

**Status:** Accepted  
**Date:** 2026-09-25  
**Phase:** 3

## Context

Built-in collectors cover AWS, Azure, GCP, Kubernetes, and a demo graph. Phase 3 needs a way for other inventories (on-prem, SaaS, a private cloud) to enter the same graph without forking `internal/collectors`.

Go's `plugin` package was rejected: it requires a matching toolchain, does not work on every OS, and cannot be implemented from another language.

## Decision

Collectors are out-of-process executables.

- The public contract lives in `sdk/collector` (schema v0 node and edge types, batch JSON, validation).
- A plugin writes one JSON object to stdout (`nodes`, `edges`) and diagnostics to stderr. Exit 0 means success.
- Go authors implement `collector.Collector` and call `collector.Run` from `main`.
- `om scan plugin -- <executable> [args...]` runs the executable, validates the batch, and upserts it. Stdout is capped at 32MiB. The plugin inherits `om`'s environment, so cloud credentials stay in the user's shell.
- Every edge endpoint must appear as a node in the same batch. Empty edge ids are filled as `source|target|type`.
- Plugins are trusted code. They run with the privileges of the user who invokes `om` and must stay read-only toward inventoried systems.

`examples/collector` is the reference plugin.

## Consequences

- Community collectors can ship as their own binaries and any language.
- Schema changes have to stay compatible with the JSON tags in `sdk/collector` and `internal/graph`.
- In-process Go plugins are not supported.

## References

- [docs/ROADMAP.md](../ROADMAP.md)
- [sdk/collector](../../sdk/collector)
- [examples/collector](../../examples/collector)
