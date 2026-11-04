# Connect a production account

The workload scan mounts disks only in a scanner account, subscription, or project that you run. Each production account grants a role that can snapshot and share. It does not grant permission to attach a disk or start an instance.

Apply the scanner stack once, then apply the production stack in every account you want to read. Terraform and OpenTofu use the same files. AWS also has CloudFormation and a shell script. Azure has an `az` script. GCP has a `gcloud` script.

| Cloud | Scanner | Production |
| --- | --- | --- |
| AWS | [`aws/scanner`](aws/scanner) | [`aws/production`](aws/production) |
| Azure | [`azure/scanner`](azure/scanner) | [`azure/production`](azure/production) |
| GCP | [`gcp/scanner`](gcp/scanner) | [`gcp/production`](gcp/production) |

Create the scanner role first. Pass its ARN, principal id, or service account into the production stack, with an external id you choose and store. The production key policy has to allow that principal to decrypt root-volume keys. The snippet is [`aws/kms-key-policy.json`](aws/kms-key-policy.json). Add the same principal to each Azure disk-encryption key vault and each GCP key that encrypts a boot disk.

Then, on the scanner worker, as root:

```bash
sudo -E ./om scan workload aws --snapshot-role "$ROLE_ARN" --external-id "$EXTERNAL_ID" --kms-key "$SCANNER_KEY"
sudo -E ./om scan workload azure
sudo -E ./om scan workload gcp
```

`AZURE_SUBSCRIPTION_ID` and `GCP_PROJECT_ID` are the production subscription and project. The worker's own subscription and project come from the instance metadata. AWS snapshots are copied into the scanner account with `--kms-key` when the source volume is encrypted.
