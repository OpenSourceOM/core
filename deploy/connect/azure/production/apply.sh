#!/bin/sh
# Grant the scanner identity permission to snapshot this subscription.
# OpenTofu and Terraform use main.tf.
set -eu

: "${AZURE_SUBSCRIPTION_ID:?set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_LOCATION:?set AZURE_LOCATION}"
: "${SCANNER_PRINCIPAL_ID:?set SCANNER_PRINCIPAL_ID}"

az group create --subscription "$AZURE_SUBSCRIPTION_ID" --name opensourceom-snapshots --location "$AZURE_LOCATION"

role=$(cat <<'EOF'
{
  "Name": "OpenSourceOM snapshot",
  "IsCustom": true,
  "Description": "Create and delete OpenSourceOM workload snapshots. Does not attach a disk.",
  "Actions": [
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Compute/snapshots/write",
    "Microsoft.Compute/snapshots/delete",
    "Microsoft.Compute/images/read",
    "Microsoft.Compute/galleries/images/versions/read",
    "Microsoft.Compute/diskEncryptionSets/read",
    "Microsoft.KeyVault/vaults/keys/wrap/action",
    "Microsoft.KeyVault/vaults/keys/unwrap/action"
  ],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/SUBSCRIPTION_ID"]
}
EOF
)
role=$(printf '%s' "$role" | sed "s#SUBSCRIPTION_ID#${AZURE_SUBSCRIPTION_ID}#")
printf '%s' "$role" > /tmp/opensourceom-snapshot-role.json
az role definition create --role-definition /tmp/opensourceom-snapshot-role.json >/dev/null 2>&1 \
  || az role definition update --role-definition /tmp/opensourceom-snapshot-role.json >/dev/null
az role assignment create \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --assignee-object-id "$SCANNER_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "OpenSourceOM snapshot"
rm -f /tmp/opensourceom-snapshot-role.json
