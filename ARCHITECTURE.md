# Architecture

## Boundaries

TriSOC Attestor is a modular monorepo with a Go security core. The CLI, REST API,
worker, and MCP adapters call application services; provider collectors implement
bounded read operations behind provider-specific interfaces; PostgreSQL owns the
canonical schema and append-only record of observations. The optional Next.js UI
is a client of the versioned REST API and does not own attestation truth.

Naming is isolated in `config/product.yaml`. Package paths use domain names such
as `control`, `evidence`, and `mcp`, avoiding product-name coupling.

## Planned repository map

```text
cmd/trisoc/          CLI entry point
internal/control/    control model, strict loader, and deterministic validation
internal/evidence/   redaction and hashing
internal/logsource/  source coverage, freshness, retention, and normalisation
internal/maturity/   SOC-CMM profile, strict loader, and readiness evaluation
internal/mcp/        MCP transport and read-only tools
controls/            reviewed, versioned control packs and JSON Schema
migrations/          canonical backend-owned PostgreSQL schema
config/              replaceable product presentation settings
apps/                API, worker, web, and docs applications as phases land
providers/           Microsoft, AWS, and Google collectors as phases land
deploy/              Docker, Helm, Bicep, CloudFormation, and Terraform assets
docs/adr/             architecture decision records
```

Folders are added when they contain functioning code; the roadmap does not use
empty directories to imply that unavailable provider features exist.

## Readiness and attestation data flow

The readiness path uses only declared, bounded assessment inputs. The CLI
combines the reports for `trisoc siem check`; MCP clients receive the two reports
from separate read-only tools and combine them in their approved workflow.

### SIEM readiness

```mermaid
sequenceDiagram
  actor U as Operator or approved agent
  participant A as CLI or MCP adapter
  participant B as Strict YAML or JSON boundary
  participant L as Log-source evaluator
  participant M as SOC-CMM evaluator
  U->>A: siem check or MCP check tools
  A->>B: bounded inventory and assessment
  B-->>A: strict decoded inputs or validation error
  par Log-source gate
    A->>L: inventory and evaluation time
    L-->>A: source, policy, and normalisation checks
  and SOC maturity gate
    A->>M: model, 27 aspects, 45 controls, evidence
    M-->>A: maturity, capability, and completeness checks
  end
  A->>A: combine reports for CLI siem check
  A-->>U: pass, fail, unknown, or incomplete with evidence references
```

### Provider attestation

```mermaid
sequenceDiagram
  actor U as Operator or approved agent
  participant A as CLI or MCP adapter
  participant P as Read-only provider collector
  participant E as Control evaluator
  participant D as PostgreSQL phase 5
  U->>A: request scoped assessment
  A->>P: bounded, paginated API operations
  P-->>A: structured observation or typed error
  A->>A: redact, normalise, hash
  A->>E: exact control version plus evidence
  E-->>A: pass, fail, warning, NA, unknown, or error
  opt Scheduled persistence in phase 5
    A->>D: append evidence, result, drift, and audit event
  end
  A-->>U: bounded explanations and evidence references
```

Collection failure bypasses compliance evaluation and becomes `unknown` or
`error`. Applicability runs before collection. Technical failure remains present
under an accepted exception.

## SIEM implementation lifecycle

```mermaid
flowchart TB
  subgraph Deploy[Deploy or onboard the SIEM]
    Review[Review prerequisites and plan] --> Validate[Validate and scan IaC]
    Validate --> Bicep[Sentinel Bicep]
    Validate --> CloudFormation[AWS CloudFormation]
    Validate --> Terraform[Google SecOps Terraform]
    Bicep --> Sentinel[Microsoft Sentinel]
    CloudFormation --> AWS[AWS security operations]
    Terraform --> Google[Google Security Operations]
    Sentinel --> Onboard[Onboard and validate telemetry]
    AWS --> Onboard
    Google --> Onboard
    Splunk[Splunk - no TriSOC IaC] --> Onboard
  end

  subgraph Evidence[Collect readiness evidence]
    Onboard --> Inventory[Log-source inventory]
    Workbook[SOC-CMM stakeholder assessment] --> Profile[27-aspect maturity profile]
    Inventory --> LogCheck[Coverage, freshness, retention, normalisation]
    Profile --> MaturityCheck[Maturity, capability, and evidence]
  end

  LogCheck --> Gate[Combined SIEM implementation gate]
  MaturityCheck --> Gate
  Gate -->|pass| Promote[Approve deployment or promotion]
  Gate -->|fail or incomplete| Rework[Remediate and collect evidence]
  Rework -.-> Onboard
  Rework -.-> Workbook
  Promote --> Attest[Read-only attestation and drift follow-up]
```

Splunk participates in CIM and operational-readiness checks but has no TriSOC
deployment baseline. The CLI combines both readiness reports in `trisoc siem
check`; MCP clients call `check_log_sources` and `check_soc_maturity` separately
and combine them in the approved agent workflow.

## Write safety

Assessment and planning are distinct from execution. A plan is content-addressed.
Approval binds an authenticated human, organisation, exact plan hash, scope, and
expiry. Apply re-checks the hash and preconditions, consumes the approval against
replay, applies only with explicit CLI `--apply`, records every step, and triggers
targeted validation. Destructive plans are never automatic.

## Persistence and tenancy

All tenant-owned tables carry `organisation_id`; service queries must scope by it.
Foreign keys preserve provenance from an assessment to its exact control version
and evidence. Database triggers prohibit updates or deletion of evidence,
results, bundles, approvals, exception decisions, and audit events. Application
tests will add PostgreSQL row-level security and cross-tenant negative cases
before multi-tenant hosting is supported.

## Observability

Structured JSON logs are mandatory and secrets are redacted before logging.
OpenTelemetry traces and Prometheus metrics arrive with the API/worker phase.
Metrics must use bounded labels; cloud resource IDs and tenant IDs are not metric
labels.
