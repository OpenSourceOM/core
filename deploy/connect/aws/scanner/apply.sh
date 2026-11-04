#!/bin/sh
# Apply the scanner instance profile with the AWS CLI.
set -eu

: "${EXTERNAL_ID:?set EXTERNAL_ID}"

trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

policy=$(cat <<EOF
{"Version":"2012-10-17","Statement":[
  {"Sid":"CopyAndAttach","Effect":"Allow","Action":["ec2:DescribeInstances","ec2:DescribeSnapshots","ec2:DescribeVolumes","ec2:CopySnapshot","ec2:CreateVolume","ec2:CreateTags","ec2:AttachVolume","ec2:DetachVolume","ec2:DeleteVolume","ec2:DeleteSnapshot"],"Resource":"*"},
  {"Sid":"AssumeProduction","Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::*:role/opensourceom-snapshot","Condition":{"StringEquals":{"sts:ExternalId":"${EXTERNAL_ID}"}}},
  {"Sid":"Keys","Effect":"Allow","Action":["kms:CreateGrant","kms:Decrypt","kms:Encrypt","kms:DescribeKey","kms:GenerateDataKeyWithoutPlaintext","kms:ReEncryptFrom","kms:ReEncryptTo"],"Resource":"*"}
]}
EOF
)

if aws iam get-role --role-name opensourceom-worker >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name opensourceom-worker --policy-document "$trust"
else
  aws iam create-role --role-name opensourceom-worker --assume-role-policy-document "$trust"
fi
aws iam put-role-policy --role-name opensourceom-worker --policy-name worker --policy-document "$policy"
aws iam create-instance-profile --instance-profile-name opensourceom-worker 2>/dev/null || true
aws iam add-role-to-instance-profile --instance-profile-name opensourceom-worker --role-name opensourceom-worker 2>/dev/null || true
aws iam get-role --role-name opensourceom-worker --query Role.Arn --output text
