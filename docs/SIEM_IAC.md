# Ready-to-deploy SIEM infrastructure

TriSOC includes reviewed starting-point infrastructure for Microsoft Sentinel,
AWS-native security operations, and Google Security Operations. Defaults favour
encryption, retention, centralised collection, health visibility, and deletion
protection. Always inspect the plan in a non-production environment and adapt
network, residency, naming, and delegated-administrator choices to your estate.

Splunk is intentionally included in log-source compliance checks but excluded
from these deployment assets.

Every platform uses the same post-deployment readiness gate: run `trisoc siem
check` with the environment's log-source inventory and completed SOC-CMM
assessment. The IaC establishes secure defaults; it cannot prove the people,
process, service, detection, or evidence requirements in the maturity profile.

## Microsoft Sentinel

The subscription-scoped Bicep deployment creates a Log Analytics workspace,
onboards Sentinel, enables Sentinel health and audit telemetry, and sends all
subscription Activity Log categories to dedicated workspace tables. Local
workspace authentication is disabled by default.

```sh
az deployment sub what-if \
  --location australiaeast \
  --template-file deploy/bicep/microsoft-sentinel/main.bicep \
  --parameters workspaceName=sentinel-production

az deployment sub create \
  --location australiaeast \
  --template-file deploy/bicep/microsoft-sentinel/main.bicep \
  --parameters workspaceName=sentinel-production
```

Set `publicNetworkAccessForIngestion` and `publicNetworkAccessForQuery` to
`Disabled` only after private endpoints and DNS are ready. Data connectors and
analytics rules are tenant-specific and remain explicit follow-on configuration.

## AWS-native security operations

The CloudFormation baseline creates an encrypted, versioned audit archive;
multi-Region organisation CloudTrail; continuous AWS Config recording;
GuardDuty protections auto-enabled for existing and future organisation
accounts; Security Hub central configuration with AWS Foundational Security Best
Practices applied at the organisation root; and Security Lake with current native
sources and lifecycle retention. Persistent data and the GuardDuty detector are
retained if the stack is deleted.

Run the stack from the organisation management account or configured delegated
administrator with the service-linked role permissions required by GuardDuty,
Security Hub, Config, and Security Lake:

```sh
aws cloudformation validate-template \
  --template-body file://deploy/cloudformation/aws-security-operations-baseline.yaml

aws cloudformation deploy \
  --stack-name trisoc-security-operations \
  --template-file deploy/cloudformation/aws-security-operations-baseline.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    OrganizationId=o-example12345 \
    OrganizationRootId=r-example1 \
    ExistingGuardDutyDetectorId=12abc34d5678example \
    DeployOrganizationTrail=true \
  --region ap-southeast-2
```

Deploy the organisation trail only in its home Region. Use StackSets for the
regional/member-account controls required by your organisation and pass
`DeployOrganizationTrail=false` outside the home Region. Review service quotas,
delegated administrators, existing recorders/trails, KMS policies, and Security
Lake rollup Regions before creation because these resources can be singleton or
organisation-scoped.

Designating a GuardDuty delegated administrator creates its regional detector.
Pass that detector ID as shown; leave the parameter empty only when GuardDuty has
not yet been enabled in the deployment account and Region. Existing Security Hub,
Config, trail, or Security Lake resources should be imported or reconciled before
deploying this greenfield baseline.

## Google Security Operations

The Terraform root enables required APIs, configures organisation-wide audit
logging, creates an aggregated organisation sink and regional Pub/Sub transport,
and provisions an authenticated Google Security Operations feed. The
subscription has deletion protection and the service account receives only the
roles needed by this ingestion path.

Google must first provision a Security Operations instance and bind it to the
Google Cloud project. Supply that instance UUID and keep the project, Chronicle
instance, Pub/Sub topic, and sink in compatible regions.

Run Terraform with an impersonated deployment service account that can manage
organisation audit configuration, logging sinks, project services, IAM bindings,
service accounts, Pub/Sub, and Chronicle feeds. It also needs
`iam.serviceAccounts.actAs` on the push identity when the subscription is
created; avoid long-lived service-account keys.

Google recommends its [console-managed direct integration](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/ingest-gcp-logs)
for standard Google Cloud telemetry. That configuration currently has no
supported Terraform resource. This root instead provisions the documented Google
Cloud Pub/Sub HTTPS push feed end to end, so it remains reviewable and deployable
as code. If direct integration is enabled separately, remove this feed path to
avoid duplicate ingestion.

```sh
cd deploy/terraform/google-secops
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars before continuing.
terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
```

The organisation audit configuration is authoritative for `allServices`. Review
the plan carefully if exclusions already exist, and use a dedicated state backend
with locking, encryption, versioning, and least-privilege access in production.
