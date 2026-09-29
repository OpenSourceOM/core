#!/usr/bin/env bash
# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0

# Renders the chart and checks scheduled collectors stay off without credentials.
set -euo pipefail

chart="$(cd "$(dirname "$0")" && pwd)"
base=(--set api.secret=test --set postgres.password=test)

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

render() {
  local name="$1"
  shift
  helm template om "$chart" "${base[@]}" "$@" >"$workdir/$name.yaml"
}

assert_absent() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if grep -qE -- "$pattern" "$file"; then
    echo "$message" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_present() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -qE -- "$pattern" "$file"; then
    echo "$message" >&2
    cat "$file" >&2
    exit 1
  fi
}

if helm template om "$chart" >/dev/null 2>"$workdir/missing-secrets.err"; then
  echo "chart rendered without required secrets" >&2
  exit 1
fi

helm lint "$chart" "${base[@]}"

render default
assert_absent "$workdir/default.yaml" "kind: CronJob" "default install created a CronJob"
assert_absent "$workdir/default.yaml" "kind: ClusterRole$" "default install created scan RBAC"
assert_absent "$workdir/default.yaml" "- demo" "default install scheduled the demo scan"

render aws-no-creds --set scan.aws.enabled=true
assert_absent "$workdir/aws-no-creds.yaml" "kind: CronJob" "AWS scan without credentials created a CronJob"

render aws \
  --set scan.aws.enabled=true \
  --set scan.aws.accessKeyId=AKIATEST \
  --set scan.aws.secretAccessKey=s3cr3t-value
helm template om "$chart" "${base[@]}" \
  --set scan.aws.enabled=true \
  --set scan.aws.accessKeyId=AKIATEST \
  --set scan.aws.secretAccessKey=s3cr3t-value \
  --show-only templates/scan-cronjob.yaml >"$workdir/aws-cron.yaml"
helm template om "$chart" "${base[@]}" \
  --set scan.aws.enabled=true \
  --set scan.aws.accessKeyId=AKIATEST \
  --set scan.aws.secretAccessKey=s3cr3t-value \
  --show-only templates/scan-secret.yaml >"$workdir/aws-secret.yaml"
assert_present "$workdir/aws-cron.yaml" "kind: CronJob" "AWS credentials did not create a CronJob"
assert_present "$workdir/aws-cron.yaml" "concurrencyPolicy: Forbid" "AWS CronJob can overlap itself"
assert_present "$workdir/aws-cron.yaml" "- scan" "AWS CronJob does not run om scan"
assert_present "$workdir/aws-cron.yaml" "- aws" "AWS CronJob does not run the aws collector"
assert_present "$workdir/aws-cron.yaml" "om-opensourceom-postgres" "AWS scan does not use the chart Postgres"
assert_present "$workdir/aws-secret.yaml" "s3cr3t-value" "inline AWS secret was not stored"
assert_absent "$workdir/aws-cron.yaml" "s3cr3t-value" "AWS secret was copied into the CronJob"
assert_absent "$workdir/aws-cron.yaml" "AKIATEST" "AWS access key was copied into the CronJob"
assert_absent "$workdir/aws-cron.yaml" "OM_API_SECRET" "scan pod received the API secret"
assert_absent "$workdir/aws-cron.yaml" "- demo" "AWS scan scheduled the demo scan"

render external-db \
  --set postgres.enabled=false \
  --set postgres.host=db.internal.example \
  --set scan.aws.enabled=true \
  --set scan.aws.serviceAccountAuth=true
assert_present "$workdir/external-db.yaml" "db.internal.example" "scan did not target the external Postgres host"
assert_absent "$workdir/external-db.yaml" "AWS_ACCESS_KEY_ID" "service account auth still mounted a static AWS secret"

cat >"$workdir/irsa.yaml" <<'EOF'
scan:
  aws:
    enabled: true
    serviceAccountAuth: true
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/opensourceom
EOF
render irsa-out -f "$workdir/irsa.yaml"
assert_present "$workdir/irsa-out.yaml" "eks.amazonaws.com/role-arn" "IRSA annotation was dropped"
assert_present "$workdir/irsa-out.yaml" "kind: CronJob" "service account auth did not schedule AWS"

render azure-no-sub --set scan.azure.enabled=true --set scan.azure.tenantId=t --set scan.azure.clientId=c --set scan.azure.clientSecret=s
assert_absent "$workdir/azure-no-sub.yaml" "kind: CronJob" "Azure scan without a subscription id created a CronJob"

both_set=(
  --set scan.aws.enabled=true
  --set scan.aws.existingSecret=aws-creds
  --set scan.azure.enabled=true
  --set scan.azure.subscriptionId=sub
  --set scan.azure.tenantId=tenant
  --set scan.azure.clientId=client
  --set scan.azure.clientSecret=azure-secret
)
render both "${both_set[@]}"
helm template om "$chart" "${base[@]}" "${both_set[@]}" --show-only templates/scan-cronjob.yaml >"$workdir/both-cron.yaml"
helm template om "$chart" "${base[@]}" "${both_set[@]}" --show-only templates/scan-secret.yaml >"$workdir/both-secret.yaml"
jobs="$(grep -c "kind: CronJob" "$workdir/both-cron.yaml")"
if [[ "$jobs" -ne 2 ]]; then
  echo "expected 2 CronJobs, found $jobs" >&2
  exit 1
fi
assert_present "$workdir/both-cron.yaml" 'name: "aws-creds"' "existing AWS secret was not referenced"
assert_absent "$workdir/both-cron.yaml" "azure-secret" "Azure client secret was copied into the CronJob spec"
assert_present "$workdir/both-secret.yaml" "AZURE_CLIENT_SECRET" "Azure client secret was not stored"

gcp_set=(
  --set scan.gcp.enabled=true
  --set scan.gcp.projectId=proj
  --set-string scan.gcp.credentialsJson='{"type":"service_account"}'
)
render gcp "${gcp_set[@]}"
helm template om "$chart" "${base[@]}" "${gcp_set[@]}" --show-only templates/scan-cronjob.yaml >"$workdir/gcp-cron.yaml"
assert_present "$workdir/gcp-cron.yaml" "GOOGLE_APPLICATION_CREDENTIALS" "GCP scan did not point at the key file"
assert_present "$workdir/gcp.yaml" "credentials.json" "GCP key was not stored"
assert_absent "$workdir/gcp-cron.yaml" "service_account" "GCP key JSON was copied into the CronJob"

render gcp-no-project --set scan.gcp.enabled=true --set scan.gcp.credentialsJson='{"type":"service_account"}'
assert_absent "$workdir/gcp-no-project.yaml" "kind: CronJob" "GCP scan without a project id created a CronJob"

render k8s --set scan.kubernetes.enabled=true --set scan.kubernetes.cluster=prod
assert_present "$workdir/k8s.yaml" "kind: ClusterRole$" "in-cluster scan did not grant cluster read"
assert_present "$workdir/k8s.yaml" "namespaces" "cluster scan cannot list namespaces"
assert_present "$workdir/k8s.yaml" "automountServiceAccountToken: true" "in-cluster scan cannot read the API"
assert_present "$workdir/k8s.yaml" 'value: "prod"' "cluster name was not passed as the graph account id"
assert_absent "$workdir/k8s.yaml" "KUBECONFIG" "in-cluster scan expected a kubeconfig file"

render k8s-ns --set scan.kubernetes.enabled=true --set scan.kubernetes.namespace=apps
assert_present "$workdir/k8s-ns.yaml" "kind: Role$" "namespace scan did not create a Role"
assert_absent "$workdir/k8s-ns.yaml" "kind: ClusterRole$" "namespace scan created a ClusterRole"
assert_absent "$workdir/k8s-ns.yaml" "namespaces" "namespace scan listed namespaces"

render k8s-kube --set scan.kubernetes.enabled=true --set scan.kubernetes.existingSecret=kube --set scan.kubernetes.cluster=prod
assert_present "$workdir/k8s-kube.yaml" "KUBECONFIG" "kubeconfig secret was not mounted"
assert_present "$workdir/k8s-kube.yaml" "automountServiceAccountToken: false" "kubeconfig scan still mounted the pod token"
assert_absent "$workdir/k8s-kube.yaml" "kind: ClusterRole$" "kubeconfig scan created in-cluster RBAC"
assert_absent "$workdir/k8s-kube.yaml" "- demo" "kubernetes scan scheduled the demo scan"

echo "helm render checks passed"
