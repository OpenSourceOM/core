# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
# Fail if Snyk reports High/Critical issues on the go.mod module graph.
#
# CLI `snyk test` with a Go toolchain uses `go list` (package-level) and can
# report no reachable paths while the GitHub-imported project still has Highs.
# Scanning only go.mod/go.sum without `go` matches that SCM module-level view.
# snyk/snyk:alpine ENTRYPOINT is `snyk`, so invoke `test` directly.
# The Snyk API is not used: this org plan is not entitled for API access.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/.snyk" "$TMP/"

docker run --rm \
  --entrypoint snyk \
  -e SNYK_TOKEN \
  -e GOFLAGS="${GOFLAGS:--buildvcs=false}" \
  -e PATH=/usr/local/bin:/usr/bin:/bin \
  -v "$TMP:/app" \
  -w /app \
  snyk/snyk:alpine \
  test --file=go.mod --severity-threshold=high --policy-path=.snyk
