variable "scanner_role_arn" {
  type        = string
  description = "ARN of opensourceom-worker in the scanner account."
}

variable "scanner_account_id" {
  type        = string
  description = "Account id that snapshots are shared with."
}

variable "external_id" {
  type        = string
  description = "Value the worker passes to sts:AssumeRole."
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.scanner_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

data "aws_iam_policy_document" "snapshot" {
  statement {
    sid = "Read"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeImages",
      "ec2:DescribeSnapshots",
      "ec2:DescribeVolumes",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CreateTaggedSnapshot"
    actions = [
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
    ]
    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*::snapshot/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/opensourceom:scan"
      values   = ["workload"]
    }
  }

  statement {
    sid       = "ShareWithScanner"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["arn:aws:ec2:*::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:Add/userId"
      values   = [var.scanner_account_id]
    }
  }

  statement {
    sid       = "Unshare"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["arn:aws:ec2:*::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:Remove/userId"
      values   = [var.scanner_account_id]
    }
  }

  statement {
    sid       = "DeleteOurSnapshots"
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["arn:aws:ec2:*::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/opensourceom:scan"
      values   = ["workload"]
    }
  }

  statement {
    sid = "EncryptedVolumes"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "snapshot" {
  name               = "opensourceom-snapshot"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role_policy" "snapshot" {
  name   = "snapshot"
  role   = aws_iam_role.snapshot.id
  policy = data.aws_iam_policy_document.snapshot.json
}

output "role_arn" {
  value = aws_iam_role.snapshot.arn
}
