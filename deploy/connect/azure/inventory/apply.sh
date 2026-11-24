#!/bin/sh
# Grant read access for om scan azure. Does not grant snapshot or disk attach.
set -eu

: "${AZURE_SUBSCRIPTION_ID:?set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_PRINCIPAL_ID:?set AZURE_PRINCIPAL_ID}"

scope="/subscriptions/${AZURE_SUBSCRIPTION_ID}"
az role assignment create \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --assignee-object-id "$AZURE_PRINCIPAL_ID" \
  --assignee-principal-type "${AZURE_PRINCIPAL_TYPE:-ServicePrincipal}" \
  --role Reader \
  --scope "$scope"
az role assignment create \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --assignee-object-id "$AZURE_PRINCIPAL_ID" \
  --assignee-principal-type "${AZURE_PRINCIPAL_TYPE:-ServicePrincipal}" \
  --role "Monitoring Reader" \
  --scope "$scope"
