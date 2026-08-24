# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
set -euo pipefail

# Create OpenSourceOM/core on GitHub and push local scaffold.
# Usage: ./scripts/push-to-github.sh

ORG="OpenSourceOM"
REPO="core"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
API="https://api.github.com"

TOKEN_FILE="${GITHUB_TOKEN_FILE:-$HOME/.config/opensourceom/token}"
if [ -z "${GITHUB_TOKEN:-}" ] && [ -f "$TOKEN_FILE" ]; then
  GITHUB_TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
  export GITHUB_TOKEN
fi

[ -n "${GITHUB_TOKEN:-}" ] || { echo "Missing token at $TOKEN_FILE"; exit 1; }

AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")

log() { printf '\n▸ %s\n' "$1"; }

repo_exists() {
  curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "$API/repos/$ORG/$REPO" | grep -q '^200$'
}

create_repo() {
  if repo_exists; then
    log "$ORG/$REPO already exists"
    return
  fi
  log "Creating $ORG/$REPO..."
  CODE=$(curl -s -o /tmp/create-core.json -w "%{http_code}" -X POST "${AUTH[@]}" \
    "$API/orgs/$ORG/repos" \
    -d '{"name":"core","description":"Open-source cloud security platform — collectors, graph engine, API","private":false,"has_issues":true,"license_template":"apache-2.0"}')
  if [ "$CODE" != "201" ]; then
    echo "Failed (HTTP $CODE):"; cat /tmp/create-core.json; exit 1
  fi
  log "Created https://github.com/$ORG/$REPO"
}

push_code() {
  cd "$PROJECT_DIR"
  if [ ! -d .git ]; then
    git init
    git branch -M main
  fi
  git add .
  if git diff --cached --quiet; then
    log "Nothing new to commit"
  else
    git commit -m "Initial core repo scaffold with Apache-2.0 license"
  fi
  git remote remove origin 2>/dev/null || true
  git remote add origin "git@github.com:$ORG/$REPO.git"
  git push -u origin main
  log "Pushed to https://github.com/$ORG/$REPO"
}

create_repo
push_code
