# ADR-0004: Read-only MCP boundary

Status: Accepted — 2026-07-14

## Decision

MCP binds to loopback, uses bounded request and response sizes, describes safety
in every tool schema, and exposes no write capability in the foundation release.
Future apply tools must call the same approval service as the CLI and cannot
treat an agent request as approval.

## Consequences

Agents can inspect controls safely today. Remote HTTP use needs an authenticated
reverse proxy or a future native authentication mode. Stdio is the recommended
local-agent transport.

