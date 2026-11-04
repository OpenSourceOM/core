variable "subscription_id" {
  type = string
}

variable "location" {
  type = string
}

variable "scanner_principal_id" {
  type        = string
  description = "Object id of the scanner subscription's opensourceom-worker managed identity."
}

resource "azurerm_resource_group" "snapshots" {
  name     = "opensourceom-snapshots"
  location = var.location
}

resource "azurerm_role_definition" "snapshot" {
  name        = "OpenSourceOM snapshot"
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Create and delete OpenSourceOM workload snapshots. Does not attach a disk."

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/snapshots/read",
      "Microsoft.Compute/snapshots/write",
      "Microsoft.Compute/snapshots/delete",
      "Microsoft.Compute/images/read",
      "Microsoft.Compute/galleries/images/versions/read",
      "Microsoft.Compute/diskEncryptionSets/read",
      "Microsoft.KeyVault/vaults/keys/wrap/action",
      "Microsoft.KeyVault/vaults/keys/unwrap/action",
    ]
  }

  assignable_scopes = ["/subscriptions/${var.subscription_id}"]
}

resource "azurerm_role_assignment" "snapshot" {
  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = azurerm_role_definition.snapshot.role_definition_resource_id
  principal_id       = var.scanner_principal_id
}
