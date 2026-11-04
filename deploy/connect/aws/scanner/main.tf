variable "external_id" {
  type        = string
  description = "Value the worker passes to sts:AssumeRole. Use the same value in every production stack."
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid = "CopyAndAttach"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeVolumes",
      "ec2:CopySnapshot",
      "ec2:CreateVolume",
      "ec2:CreateTags",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:DeleteVolume",
      "ec2:DeleteSnapshot",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "AssumeProduction"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/opensourceom-snapshot"]
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }

  statement {
    sid = "Keys"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "worker" {
  name               = "opensourceom-worker"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role_policy" "worker" {
  name   = "worker"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker.json
}

resource "aws_iam_instance_profile" "worker" {
  name = "opensourceom-worker"
  role = aws_iam_role.worker.name
}

output "role_arn" {
  value = aws_iam_role.worker.arn
}

output "instance_profile" {
  value = aws_iam_instance_profile.worker.name
}
