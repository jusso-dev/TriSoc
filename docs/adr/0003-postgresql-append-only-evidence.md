# ADR-0003: PostgreSQL append-only evidence

Status: Accepted — 2026-07-14

## Decision

PostgreSQL is the canonical store. Evidence, control results, bundles, approval
decisions, exception decisions, and audit events are append-only and protected
by database triggers. Results reference exact control versions.

## Consequences

History cannot be silently rewritten by application bugs. Corrections are new
events. Storage retention needs explicit governance and evidence payloads must be
redacted before insertion.

