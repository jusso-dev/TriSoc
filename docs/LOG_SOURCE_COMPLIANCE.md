# Log-source compliance and normalisation

TriSOC evaluates a declared log-source inventory without accessing event payloads.
The inventory records whether each source is enabled, fresh, retained for long
enough, and mapped to the normalisation standard expected for its destination.

```sh
trisoc log-sources check examples/log-source-inventory.yaml
```

Use `--at` to make CI and audit evidence deterministic:

```sh
trisoc log-sources check examples/log-source-inventory.yaml \
  --at 2026-07-16T08:00:00Z --output json
```

The check fails closed when a required source is absent, disabled, stale, below
the retention or normalisation-coverage threshold, mapped to the wrong standard,
or has no validated mapping. Missing and future event timestamps produce an
`unknown` freshness result and keep the inventory noncompliant.

| Platform | Required normalisation |
| --- | --- |
| Microsoft Sentinel | [Advanced Security Information Model (ASIM)](https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-parsers) |
| AWS Security Lake | [Open Cybersecurity Schema Framework (OCSF)](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) |
| Google Security Operations | [Unified Data Model (UDM)](https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview) |
| Splunk | [Common Information Model (CIM)](https://help.splunk.com/en/data-management/common-information-model/6.0/introduction/overview-of-the-splunk-common-information-model) |

The inventory parser is strict: unknown fields, YAML aliases, custom tags,
multiple documents, oversized inputs, and duplicate source identifiers are
rejected. Platform aliases are accepted and reported in the canonical form.

MCP clients can run the same evaluator with `check_log_sources`. The tool accepts
the inventory as structured JSON and an optional RFC 3339 evaluation time.

For deployment approval, use the combined `trisoc siem check` workflow so this
inventory and the required [SOC-CMM maturity profile](SOC_MATURITY.md) must both
pass.

This is an evidence check, not proof that every emitted event is semantically
correct. Keep mapping validation evidence, sample events, and destination-native
health monitoring in the operational assurance process.
