# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
# Fail if Snyk reports High/Critical issues on the go.mod module graph.
#
# Current Snyk CLI requires `go`. CLI `snyk test` is package-level (`go list`),
# while the GitHub-imported project is module-level (`go mod graph`). This step
# blank-imports every non-internal package from required modules, then scans
# with snyk/snyk:golang.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/.snyk" "$TMP/"
cd "$ROOT"
go mod download

python3 - "$TMP/scan.go" <<'PY'
import json
import pathlib
import subprocess
import sys

out = pathlib.Path(sys.argv[1])


def go_out(*args: str) -> str:
    proc = subprocess.run(["go", *args], check=True, text=True, capture_output=True)
    return proc.stdout


def parse_json_stream(raw: str) -> list[dict]:
    dec = json.JSONDecoder()
    objs: list[dict] = []
    idx = 0
    raw = raw.strip()
    while idx < len(raw):
        obj, idx = dec.raw_decode(raw, idx)
        objs.append(obj)
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
    return objs


mods = [m for m in parse_json_stream(go_out("list", "-m", "-json", "all")) if not m.get("Main")]
dirs = [m["Dir"] for m in mods if m.get("Dir")]
if not dirs:
    sample = ", ".join(m.get("Path", "?") for m in mods[:8])
    raise SystemExit(
        f"go list -m -json all returned {len(mods)} modules but none had Dir "
        f"(go mod download may have failed). sample: {sample}"
    )

pkgs: set[str] = set()
batch = 20
for i in range(0, len(dirs), batch):
    chunk = [f"{d}/..." for d in dirs[i : i + batch]]
    proc = subprocess.run(
        ["go", "list", "-f", "{{.ImportPath}}", *chunk],
        check=False,
        text=True,
        capture_output=True,
    )
    for line in proc.stdout.splitlines():
        p = line.strip()
        if not p or p == "C" or "/internal" in p:
            continue
        pkgs.add(p)
    if proc.returncode != 0 and not proc.stdout.strip() and i == 0:
        sys.stderr.write(proc.stderr[:2000])

lines = ["package modscan", "", "import ("]
for p in sorted(pkgs):
    lines.append(f'\t_ "{p}"')
lines.append(")")
lines.append("")
out.write_text("\n".join(lines))
print(
    f"blank-imported {len(pkgs)} packages from {len(dirs)}/{len(mods)} downloaded modules",
    flush=True,
)
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
