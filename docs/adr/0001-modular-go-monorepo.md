# ADR-0001: Modular Go monorepo

Status: Accepted — 2026-07-14

## Decision

Use a backend-owned Go module for the CLI, API, workers, collectors, attestation
engine, and MCP server. Add the Next.js management application as a separate
workspace when its API contract exists. Keep product presentation names in
configuration and domain package names stable.

## Consequences

Core security decisions share types and tests without network hops. Applications
remain independently deployable. Provider SDK size must be controlled through
separate packages and build review.

