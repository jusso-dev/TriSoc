# Local MCP server

Start the recommended stdio transport:

```sh
TRISOC_CONTROL_DIR=/absolute/path/to/controls trisoc mcp serve --transport stdio
```

Catalogue tools are `list_controls`, `get_control`, and
`validate_control_bundle`. Sentinel adds `discover_microsoft_sentinel`,
`run_microsoft_sentinel_attestation`, and
`generate_microsoft_sentinel_bicep`. Discovery/attestation require the read-only
permissions documented in `PROVIDER_PERMISSIONS.md`; planning makes no cloud
change. Unknown arguments are rejected and collection calls have a two-minute
deadline.

AWS adds `discover_aws_security_operations`,
`run_aws_security_operations_attestation`, and
`generate_aws_cloudformation`. Region lists are capped at 40, standards at 50,
and OpenSearch APIs are called only for `security_lake_with_opensearch` or
`full_aws_native_soc`. The MCP schema deliberately has no external-ID or static
credential field; configure those through the local AWS shared profile or
workload identity. AWS calls have a three-minute deadline.

`check_log_sources` evaluates a structured inventory for source presence,
enablement, freshness, retention, and platform-native normalisation. It supports
Microsoft Sentinel/ASIM, AWS Security Lake/OCSF, Google Security Operations/UDM,
and Splunk/CIM without reading raw events or making a cloud change.

`check_soc_maturity` evaluates a structured `SOCMaturityAssessment` against the
embedded SOC-CMM 2.4.2 Basic profile. It requires all 27 aspect results,
evidence, default maturity/capability targets, and the Log Management and Log
Monitoring implementation controls. Missing evidence remains incomplete. The
profile is attributed and documented in `docs/SOC_MATURITY.md`.

For local HTTP:

```sh
trisoc mcp serve --transport http --listen 127.0.0.1:8787
```

Compose sets `TRISOC_MCP_CONTAINER_MODE=true` only because the container wildcard
bind is published on host loopback. Do not use that setting on a host or publish
the container port externally. A non-loopback native server instead requires a
random `TRISOC_MCP_AUTH_TOKEN` of at least 32 characters and checks it as a Bearer
token, but TLS termination and an authenticated reverse proxy are still required
for any non-local deployment.

Protocol smoke test:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | trisoc mcp serve --transport stdio
```

Logs go only to stderr so they cannot corrupt stdio JSON-RPC. MCP responses never
include credentials or unrestricted cloud log content. Future write tools will
reject calls without an independently recorded human approval bound to the exact
plan hash.
