# AWS-native security operations provider

Phase 3 uses AWS SDK for Go v2 as its primary interface. Credential resolution
supports shared and IAM Identity Center profiles, environment/web identity,
ECS/EC2 workload credentials, and an optional `AssumeRole`. Tokens and access
keys are neither accepted by the MCP schema nor persisted.

## Architectures

Choose one explicitly:

- `security_lake_only`
- `security_lake_with_opensearch`
- `security_hub_findings_centric`
- `existing_third_party_siem_export`
- `full_aws_native_soc`

OpenSearch discovery occurs only for the two architectures that name it. No
OpenSearch deployment is generated or applied by the provider.

## Read-only workflow

```sh
trisoc aws discover \
  --profile security-audit \
  --role-arn arn:aws:iam::111122223333:role/TriSOCAttestorAssessment \
  --home-region ap-southeast-2 \
  --regions ap-southeast-2,us-east-1 \
  --architecture full_aws_native_soc \
  --require-delegated-admins \
  --require-security-lake \
  --securityhub-standards aws-foundational-security-best-practices \
  --output json
```

The assessment is bounded to declared Regions. Organizations pagination stops
at 10,000 accounts and OpenSearch inventory at 1,000 domains. A provider error
aborts that evidence snapshot; `attest` then records every dependent result as
`unknown` instead of producing false failures.

## Planning

```sh
trisoc aws plan --trail-name trisoc-organization-trail --output cloudformation > plan.json
```

The generated template is a plan, not an apply path. It creates a retained,
encrypted and non-public S3 bucket plus an organization-wide multi-Region trail
with read/write management events and log-file validation. Review the supplied
organization ID, the existing KMS key policy, storage/ingestion cost, retention,
and rollback handling before deployment. TriSOC does not automatically create
or resize OpenSearch.

## Current boundary

The initial collector operates with one executing or assumed role and inspects
organization-level and regional configuration visible to it. Full member-account
fan-out, Security Lake source/subscriber health, GuardDuty protection-plan detail,
finding routing, and OpenSearch Security Analytics detector health are later AWS
control-pack increments. Missing access is never treated as a pass.
