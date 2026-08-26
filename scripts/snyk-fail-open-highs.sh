# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
# Fail if Snyk reports High/Critical issues on the go.mod module graph.
#
# CLI `snyk test` with a Go toolchain uses `go list` (package-level) and can
# report no reachable paths while the GitHub-imported project still has Highs.
# Scanning only go.mod/go.sum without `go` matches that SCM module-level view.
# The Snyk API is not used: this org plan is not entitled for API access.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/.snyk" "$TMP/"

docker run --rm \
  -e SNYK_TOKEN \
  -e GOFLAGS="${GOFLAGS:--buildvcs=false}" \
  -v "$TMP:/app" \
  -w /app \
  snyk/snyk:alpine \
  sh -c 'command -v go >/dev/null 2>&1 && echo "error: go present in snyk/snyk:alpine; module-level fallback will not run" >&2 && exit 2; snyk test --file=go.mod --severity-threshold=high --policy-path=.snyk'
