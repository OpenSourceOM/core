<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# UI

Web console for exploring the security graph, reviewing prioritized findings, and visualizing attack paths.

**Phase 1:** Static console embedded in the API (`internal/api/web/`). Run `om serve` and open http://localhost:8080.

Features:

- Graph snapshot and named path query overlay
- Findings list with severity badges
- Stats dashboard (nodes, edges, workloads, findings)

Future: split into a dedicated frontend package with richer filtering and remediation workflows.
