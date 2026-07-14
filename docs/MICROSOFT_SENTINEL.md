# Microsoft Sentinel provider

Phase 2 uses the official Azure SDK for Go as its primary interface. The default
credential chain supports Azure CLI development credentials, managed identity,
workload identity federation, and environment-configured service principals.
Tokens are held by the SDK credential implementation and are never persisted.

## Read-only discovery

```sh
trisoc azure discover \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --resource-group security-operations \
  --workspace sentinel-production \
  --required-connectors AzureActiveDirectory,AzureActivity \
  --expected-tables SigninLogs,AuditLogs,AzureActivity \
  --require-automation \
  --output json
```

Discovery reads the workspace, Sentinel onboarding state, native connector
resources, analytics rules, automation rules, SentinelHealth/SentinelAudit, and
expected table freshness. All SDK list calls follow Azure pagination.

`trisoc azure attest` performs the same discovery and evaluates the latest active
Microsoft control versions. A collection or CEL error is returned as `unknown`,
never coerced to pass or fail. Organisation-policy controls for connectors,
telemetry, and automation return `not_applicable` unless requested on the target.

## Telemetry baseline

Table identifiers are restricted to Log Analytics identifier syntax before they
are inserted into KQL. The initial baseline compares the latest hour with the
same hour seven days earlier and exposes the raw counts and percentage. This is a
starting signal; the 14-day weekday/weekend robust baseline remains phase 5 work.

## Planning

`trisoc azure plan` generates Bicep for the two safe supported plan types:
Sentinel onboarding and increasing workspace retention. It never executes the
plan. Connector, detection, and automation findings remain manual because their
licensing, duplication, query, identity, and cost requirements need review.

Generated Bicep uses published resource types:

- `Microsoft.SecurityInsights/onboardingStates@2024-09-01`
- `Microsoft.OperationalInsights/workspaces@2025-07-01`

## Known limits

- Microsoft Graph, Defender XDR, Content Hub package inventory, Logic App run
  internals, RBAC assignments, and table-level retention are not yet collected.
- Health queries require their Sentinel tables/functions to exist. An API or KQL
  error stops discovery and is reported explicitly rather than becoming failure.
- The SDK does not reveal which member of the default credential chain succeeded;
  set `AZURE_CLIENT_ID` for a stable service-principal or workload identity label.

