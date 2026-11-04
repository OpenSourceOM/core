variable "subscription_id" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group" {
  type        = string
  description = "Resource group of the worker VM. Disks are created here."
}

resource "azurerm_user_assigned_identity" "worker" {
  name                = "opensourceom-worker"
  location            = var.location
  resource_group_name = var.resource_group
}

resource "azurerm_role_definition" "worker" {
  name        = "OpenSourceOM worker"
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Attach workload disks to the scanner VM."

  permissions {
    actions = [
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
      "Microsoft.KeyVault/vaults/keys/unwrap/action",
    ]
  }

  assignable_scopes = ["/subscriptions/${var.subscription_id}"]
}

resource "azurerm_role_assignment" "worker" {
  scope              = "/subscriptions/${var.subscription_id}/resourceGroups/${var.resource_group}"
  role_definition_id = azurerm_role_definition.worker.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.worker.principal_id
}

output "principal_id" {
  value = azurerm_user_assigned_identity.worker.principal_id
}
