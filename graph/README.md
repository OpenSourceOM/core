<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Graph engine

Stores the security graph and runs path queries for attack-path analysis and prioritization.

## Responsibilities

- Persist nodes and edges (workloads, identities, findings, reachability)
- Execute path queries (e.g. internet-exposed → critical CVE → prod datastore)
- Compute derived edges (transitive reachability, blast radius)

Implementation TBD. See [docs/ROADMAP.md](../docs/ROADMAP.md).
