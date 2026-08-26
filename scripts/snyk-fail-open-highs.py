# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0
"""Fail if a Snyk-monitored OpenSourceOM/core go.mod project has open High or Critical vulns."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "https://api.snyk.io"
REPO_NEEDLES = ("opensourceom/core",)
GOMOD_TYPES = {"gomodules", "golang", "govendor"}


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def api(token: str, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:2000]
        die(f"Snyk API {method} {path} failed: HTTP {e.code}\n{detail}")
    except urllib.error.URLError as e:
        die(f"Snyk API {method} {path} failed: {e}")
    if not raw:
        return {}
    return json.loads(raw)


def is_core_gomod(project: dict[str, Any]) -> bool:
    name = str(project.get("name") or "")
    name_l = name.lower()
    pkg = str(project.get("type") or project.get("packageManager") or "").lower()
    remote = str(project.get("remoteRepoUrl") or "").lower()
    blob = f"{name_l} {remote}"
    if not any(n in blob for n in REPO_NEEDLES):
        return False
    if project.get("isActive") is False:
        return False
    if pkg in GOMOD_TYPES or "go.mod" in name_l:
        return True
    # CLI monitor often uses the module path with no :go.mod suffix.
    stem = name_l.split(":", 1)[0].strip()
    return ":" not in name_l and stem in {
        "github.com/opensourceom/core",
        "opensourceom/core",
    }


def list_orgs(token: str) -> list[dict[str, Any]]:
    payload = api(token, "GET", "/v1/orgs")
    orgs = payload.get("orgs")
    if not isinstance(orgs, list) or not orgs:
        die("Snyk API returned no organizations for this token")
    return orgs


def list_projects(token: str, org_id: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    page = 1
    while page <= 50:
        q = urllib.parse.urlencode({"perPage": 100, "page": page})
        payload = api(token, "GET", f"/v1/org/{org_id}/projects?{q}")
        batch = payload.get("projects")
        if not isinstance(batch, list) or not batch:
            break
        found.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return found


def high_issues(token: str, org_id: str, project_id: str) -> list[dict[str, Any]]:
    payload = api(
        token,
        "POST",
        f"/v1/org/{org_id}/project/{project_id}/aggregated-issues",
        {
            "filters": {
                "severities": ["high", "critical"],
                "types": ["vuln"],
                "ignored": False,
                "patched": False,
            }
        },
    )
    issues = payload.get("issues")
    if isinstance(issues, dict):
        issues = issues.get("vulnerabilities") or []
    if not isinstance(issues, list):
        return []
    out = []
    for issue in issues:
        if not isinstance(issue, dict) or issue.get("isIgnored") or issue.get("isPatched"):
            continue
        data = issue.get("issueData") if isinstance(issue.get("issueData"), dict) else {}
        sev = str(data.get("severity") or issue.get("severity") or "").lower()
        if sev in {"high", "critical"}:
            out.append(issue)
    return out


def issue_line(issue: dict[str, Any]) -> str:
    data = issue.get("issueData") if isinstance(issue.get("issueData"), dict) else {}
    title = data.get("title") or issue.get("id") or "unknown"
    sev = data.get("severity") or "high"
    pkg = issue.get("pkgName") or "unknown"
    versions = issue.get("pkgVersions") or []
    ver = versions[0] if versions else ""
    loc = f"{pkg}@{ver}" if ver else str(pkg)
    return f"  [{sev}] {title} ({loc})"


def main() -> None:
    token = os.environ.get("SNYK_TOKEN", "").strip()
    if not token:
        die("SNYK_TOKEN is not set")

    matched: list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]] = []
    for org in list_orgs(token):
        org_id = org.get("id")
        org_slug = org.get("slug") or org.get("name") or org_id
        if not org_id:
            continue
        for project in list_projects(token, str(org_id)):
            if not is_core_gomod(project):
                continue
            pid = str(project.get("id") or "")
            if not pid:
                continue
            issues = high_issues(token, str(org_id), pid)
            matched.append((str(org_slug), pid, project, issues))

    if not matched:
        die(
            "No Snyk project found for OpenSourceOM/core go.mod. "
            "Install the Snyk GitHub App or run snyk monitor first."
        )

    failed = False
    for org_slug, pid, project, issues in matched:
        name = project.get("name") or pid
        origin = project.get("origin") or "unknown"
        url = f"https://app.snyk.io/org/{org_slug}/project/{pid}"
        if not issues:
            print(f"OK: {name} ({origin}) has no open High/Critical vulns")
            print(f"    {url}")
            continue
        failed = True
        print(f"FAIL: {name} ({origin}) has {len(issues)} open High/Critical vuln(s)")
        print(f"      {url}")
        for line in issues[:20]:
            print(issue_line(line))
        if len(issues) > 20:
            print(f"  … {len(issues) - 20} more")

    if failed:
        die("Monitored Snyk project has open High or Critical vulnerabilities.")


if __name__ == "__main__":
    main()
