#!/bin/sh
# Apply the production snapshot role with the AWS CLI.
# Terraform and OpenTofu use main.tf. CloudFormation uses cloudformation.yaml.
set -eu

: "${SCANNER_ROLE_ARN:?set SCANNER_ROLE_ARN}"
: "${SCANNER_ACCOUNT_ID:?set SCANNER_ACCOUNT_ID}"
: "${EXTERNAL_ID:?set EXTERNAL_ID}"

trust=$(cat <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"${SCANNER_ROLE_ARN}"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"${EXTERNAL_ID}"}}}]}
EOF
)

policy=$(cat <<EOF
{"Version":"2012-10-17","Statement":[
  {"Sid":"Read","Effect":"Allow","Action":["ec2:DescribeInstances","ec2:DescribeImages","ec2:DescribeSnapshots","ec2:DescribeVolumes"],"Resource":"*"},
  {"Sid":"CreateTaggedSnapshot","Effect":"Allow","Action":["ec2:CreateSnapshot","ec2:CreateTags"],"Resource":["arn:aws:ec2:*:*:volume/*","arn:aws:ec2:*::snapshot/*"],"Condition":{"StringEquals":{"aws:RequestTag/opensourceom:scan":"workload"}}},
  {"Sid":"ShareWithScanner","Effect":"Allow","Action":"ec2:ModifySnapshotAttribute","Resource":"arn:aws:ec2:*::snapshot/*","Condition":{"StringEquals":{"ec2:Add/userId":"${SCANNER_ACCOUNT_ID}"}}},
  {"Sid":"Unshare","Effect":"Allow","Action":"ec2:ModifySnapshotAttribute","Resource":"arn:aws:ec2:*::snapshot/*","Condition":{"StringEquals":{"ec2:Remove/userId":"${SCANNER_ACCOUNT_ID}"}}},
  {"Sid":"DeleteOurSnapshots","Effect":"Allow","Action":"ec2:DeleteSnapshot","Resource":"arn:aws:ec2:*::snapshot/*","Condition":{"StringEquals":{"ec2:ResourceTag/opensourceom:scan":"workload"}}},
  {"Sid":"EncryptedVolumes","Effect":"Allow","Action":["kms:CreateGrant","kms:Decrypt","kms:DescribeKey","kms:ReEncryptFrom","kms:ReEncryptTo"],"Resource":"*"}
]}
EOF
)

if aws iam get-role --role-name opensourceom-snapshot >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name opensourceom-snapshot --policy-document "$trust"
else
  aws iam create-role --role-name opensourceom-snapshot --assume-role-policy-document "$trust"
fi
aws iam put-role-policy --role-name opensourceom-snapshot --policy-name snapshot --policy-document "$policy"
aws iam get-role --role-name opensourceom-snapshot --query Role.Arn --output text
