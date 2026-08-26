<!--
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
-->

# Report a vulnerability

The OpenSourceOM team takes security seriously. We appreciate responsible disclosure.

## Contact

Email **security@opensourceom.org** with:

- Description of the issue
- Steps to reproduce
- Impact assessment (if known)
- Your preferred contact (optional)

We aim to acknowledge reports within **72 hours**.

## Scope

In scope:

- OpenSourceOM `core` repository and official releases
- Official deployment manifests in this repo
- The project website if it affects user safety (e.g. XSS on opensourceom.org)

Out of scope:

- Third-party dependencies (report upstream; we will track CVEs). Dependabot opens weekly PRs. Snyk scans `go.mod` in GitHub Actions when `SNYK_TOKEN` is set; install the [Snyk GitHub App](https://github.com/apps/snyk) on the OpenSourceOM org (include `core`) so the project is imported. The public `snyk.io/test/github/...` badge does not detect Go modules reliably.
- Social engineering, physical attacks, denial of service

## Safe harbor

We support good-faith research. Do not access data that is not yours, exfiltrate customer data, or disrupt services.

## Disclosure

We prefer coordinated disclosure. We will work with you on timing and credit unless you prefer anonymity.
