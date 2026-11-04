variable "project_id" {
  type = string
}

variable "scanner_service_account" {
  type        = string
  description = "Email of the scanner project's opensourceom-worker service account."
}

resource "google_project_iam_custom_role" "snapshot" {
  role_id     = "opensourceomSnapshot"
  title       = "OpenSourceOM snapshot"
  description = "Create and delete workload snapshots and grant read of boot images. Does not attach a disk."
  permissions = [
    "compute.instances.list",
    "compute.instances.get",
    "compute.disks.list",
    "compute.disks.createSnapshot",
    "compute.regionDisks.createSnapshot",
    "compute.snapshots.create",
    "compute.snapshots.get",
    "compute.snapshots.delete",
    "compute.snapshots.useReadOnly",
    "compute.images.list",
    "compute.images.get",
    "compute.images.useReadOnly",
    "compute.zoneOperations.get",
    "compute.globalOperations.get",
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToEncrypt",
  ]
  project = var.project_id
}

resource "google_project_iam_member" "snapshot" {
  project = var.project_id
  role    = google_project_iam_custom_role.snapshot.id
  member  = "serviceAccount:${var.scanner_service_account}"
}
