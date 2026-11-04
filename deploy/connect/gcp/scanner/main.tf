variable "project_id" {
  type = string
}

resource "google_service_account" "worker" {
  account_id   = "opensourceom-worker"
  display_name = "OpenSourceOM worker"
  project      = var.project_id
}

resource "google_project_iam_custom_role" "worker" {
  role_id     = "opensourceomWorker"
  title       = "OpenSourceOM worker"
  description = "Create a disk from a shared snapshot and attach it to the scanner instance."
  permissions = [
    "compute.instances.list",
    "compute.instances.get",
    "compute.disks.create",
    "compute.disks.get",
    "compute.disks.delete",
    "compute.disks.useReadOnly",
    "compute.instances.attachDisk",
    "compute.instances.detachDisk",
    "compute.zoneOperations.get",
    "compute.globalOperations.get",
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToEncrypt",
  ]
  project = var.project_id
}

resource "google_project_iam_member" "worker" {
  project = var.project_id
  role    = google_project_iam_custom_role.worker.id
  member  = "serviceAccount:${google_service_account.worker.email}"
}

output "service_account" {
  value = google_service_account.worker.email
}
