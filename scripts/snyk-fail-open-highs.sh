# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
# Fail if Snyk reports High/Critical issues on the go.mod module graph.
#
# Current Snyk CLI requires `go` (alpine without a toolchain errors
# SNYK-CLI-0000). CLI `snyk test` is package-level (`go list`), while the
# GitHub-imported project is module-level (`go mod graph`), so unused
# packages inside required modules never appear. This step builds a tiny
# module that blank-imports every non-internal package from those modules,
# then scans it with snyk/snyk:golang.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/.snyk" "$TMP/"
cd "$ROOT"
go mod download

python3 - "$TMP/scan.go" <<'PY'
import pathlib
import subprocess
import sys

out = pathlib.Path(sys.argv[1])
mods = subprocess.check_output(
    ["go", "list", "-m", "-f", "{{if not .Main}}{{.Path}}{{end}}", "all"],
    text=True,
).splitlines()
patterns = [f"{m}/..." for m in mods if m.strip()]
pkgs: set[str] = set()
# Batch to stay under ARG_MAX.
batch = 40
for i in range(0, len(patterns), batch):
    chunk = patterns[i : i + batch]
    proc = subprocess.run(
        [
            "go",
            "list",
            "-e",
            "-f",
            "{{if and (not .Standard) (ne .Name \"main\")}}{{.ImportPath}}{{end}}",
            *chunk,
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    for line in proc.stdout.splitlines():
        p = line.strip()
        if not p or "/internal" in p or p == "C":
            continue
        pkgs.add(p)

lines = [
    "package modscan",
    "",
    "import (",
]
for p in sorted(pkgs):
    lines.append(f'\t_ "{p}"')
lines.append(")")
lines.append("")
out.write_text("\n".join(lines))
print(f"blank-imported {len(pkgs)} packages from {len(patterns)} modules", flush=True)
if not pkgs:
    raise SystemExit("no third-party packages found for module-graph Snyk scan")
PY

docker run --rm \
  --entrypoint snyk \
  -e SNYK_TOKEN \
  -e GOFLAGS="${GOFLAGS:--buildvcs=false}" \
  -e GOTOOLCHAIN=local \
  -v "$TMP:/app" \
  -w /app \
  snyk/snyk:golang \
  test --file=go.mod --severity-threshold=high --policy-path=.snyk
