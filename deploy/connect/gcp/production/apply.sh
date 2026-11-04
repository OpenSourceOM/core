#!/bin/sh
# Grant the scanner service account permission to snapshot this project.
set -eu

: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID}"
: "${SCANNER_SERVICE_ACCOUNT:?set SCANNER_SERVICE_ACCOUNT}"

permissions="compute.instances.list,compute.instances.get,compute.disks.list,compute.disks.createSnapshot,compute.regionDisks.createSnapshot,compute.snapshots.create,compute.snapshots.get,compute.snapshots.delete,compute.snapshots.useReadOnly,compute.images.list,compute.images.get,compute.images.useReadOnly,compute.zoneOperations.get,compute.globalOperations.get,cloudkms.cryptoKeyVersions.useToDecrypt,cloudkms.cryptoKeyVersions.useToEncrypt"

if gcloud iam roles describe opensourceomSnapshot --project "$GCP_PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam roles update opensourceomSnapshot --project "$GCP_PROJECT_ID" --permissions "$permissions"
else
  gcloud iam roles create opensourceomSnapshot --project "$GCP_PROJECT_ID" \
    --title "OpenSourceOM snapshot" \
    --description "Create and delete workload snapshots and grant read of boot images. Does not attach a disk." \
    --permissions "$permissions"
fi
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member "serviceAccount:${SCANNER_SERVICE_ACCOUNT}" \
  --role "projects/${GCP_PROJECT_ID}/roles/opensourceomSnapshot"
