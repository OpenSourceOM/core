#!/bin/sh
# Create the scanner identity and let it attach disks in this resource group.
set -eu

: "${AZURE_SUBSCRIPTION_ID:?set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_LOCATION:?set AZURE_LOCATION}"
: "${AZURE_RESOURCE_GROUP:?set AZURE_RESOURCE_GROUP}"

az identity create \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name opensourceom-worker \
  --location "$AZURE_LOCATION"
principal=$(az identity show \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name opensourceom-worker \
  --query principalId --output tsv)

scope="/subscriptions/${AZURE_SUBSCRIPTION_ID}"
assignment="/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP}"
role=$(cat <<EOF
{
  "Name": "OpenSourceOM worker",
  "IsCustom": true,
  "Description": "Attach workload disks to the scanner VM.",
  "Actions": [
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/disks/write",
    "Microsoft.Compute/disks/delete",
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Compute/images/read",
    "Microsoft.Compute/galleries/images/versions/read",
    "Microsoft.Compute/virtualMachines/attachDetachDataDisks/action",
    "Microsoft.Compute/diskEncryptionSets/read",
    "Microsoft.KeyVault/vaults/keys/wrap/action",
    "Microsoft.KeyVault/vaults/keys/unwrap/action"
  ],
  "NotActions": [],
  "AssignableScopes": ["${scope}"]
}
EOF
)
printf '%s' "$role" > /tmp/opensourceom-worker-role.json
az role definition create --role-definition /tmp/opensourceom-worker-role.json >/dev/null 2>&1 \
  || az role definition update --role-definition /tmp/opensourceom-worker-role.json >/dev/null
az role assignment create \
  --scope "$assignment" \
  --assignee-object-id "$principal" \
  --assignee-principal-type ServicePrincipal \
  --role "OpenSourceOM worker"
rm -f /tmp/opensourceom-worker-role.json
printf '%s\n' "$principal"
