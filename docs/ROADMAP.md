# Proposed GitHub milestones and issues

The repository has no configured GitHub remote yet. Create the following
milestones when it is published; each bullet is intended to become one or more
reviewable issues with acceptance tests.

## 1 — Foundation

Control schema and validator; canonical migration; evidence hashing and
redaction; CLI; read-only MCP catalogue; Compose; ADRs and threat model; CI.

## 2 — Microsoft Sentinel

Azure credential chain; scope discovery; ARM/Graph/Log Analytics clients; ten
reviewed controls; sanitised contract fixtures; Bicep planning; permission role.

## 3 — AWS security operations

Organizations and regional discovery; GuardDuty, Security Hub, CloudTrail,
Config and Security Lake collectors; ten controls; CloudFormation plans;
cross-account permission bundles; optional OpenSearch module.

## 4 — Google Security Operations

ADC/federation; organisation/SCC/Logging/SecOps discovery; feeds, UDM and YARA-L
health; ten controls; Terraform plans; read/deploy custom roles.

## 5 — Continuous attestation

Job scheduler; freshness; drift transitions; signed hash chain; exception expiry;
notification deduplication and recovery; JSON/HTML/PDF/SARIF exports.

## 6 — Management UI

Next.js 16; Better Auth; passkeys/TOTP/recovery; accessible overview, findings,
evidence, drift, telemetry, detection, plan, exception, report and audit pages.

## 7 — Enterprise hardening

OIDC/SAML; RLS and tenant isolation; advanced RBAC/ABAC; KMS; external secrets;
Helm; HA workers; rate limits; signed release provenance and disaster recovery.

## 8 — Community controls

Signed packs; registry; maintainer workflow; guidance diffs; compatibility
matrix; provenance verification; contributor validation service.

