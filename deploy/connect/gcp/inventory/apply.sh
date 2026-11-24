#!/bin/sh
# Grant read access for om scan gcp. Does not grant snapshot or disk attach.
set -eu

: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID}"
: "${GCP_MEMBER:?set GCP_MEMBER}"

for role in \
  "roles/viewer" \
  "roles/iam.securityReviewer" \
  "roles/iam.serviceAccountViewer" \
  "roles/logging.viewer"
do
  gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
    --member "$GCP_MEMBER" \
    --role "$role" \
    --condition=None
done
