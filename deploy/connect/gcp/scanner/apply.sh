#!/bin/sh
# Create the scanner service account and let it attach disks in this project.
set -eu

: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID}"

gcloud iam service-accounts create opensourceom-worker --project "$GCP_PROJECT_ID" \
  --display-name "OpenSourceOM worker" 2>/dev/null || true
email="opensourceom-worker@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

permissions="compute.instances.list,compute.instances.get,compute.disks.create,compute.disks.get,compute.disks.delete,compute.disks.useReadOnly,compute.instances.attachDisk,compute.instances.detachDisk,compute.zoneOperations.get,compute.globalOperations.get,cloudkms.cryptoKeyVersions.useToDecrypt,cloudkms.cryptoKeyVersions.useToEncrypt"

if gcloud iam roles describe opensourceomWorker --project "$GCP_PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam roles update opensourceomWorker --project "$GCP_PROJECT_ID" --permissions "$permissions"
else
  gcloud iam roles create opensourceomWorker --project "$GCP_PROJECT_ID" \
    --title "OpenSourceOM worker" \
    --description "Create a disk from a shared snapshot and attach it to the scanner instance." \
    --permissions "$permissions"
fi
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member "serviceAccount:${email}" \
  --role "projects/${GCP_PROJECT_ID}/roles/opensourceomWorker"
printf '%s\n' "$email"
