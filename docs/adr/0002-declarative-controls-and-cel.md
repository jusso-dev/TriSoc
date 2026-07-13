# ADR-0002: Declarative controls and CEL

Status: Accepted — 2026-07-14

## Decision

Controls use strict, versioned YAML and retain vendor-specific evidence. CEL is
the only expression language. The validation environment exposes dynamic
`evidence` and no filesystem, network, process, clock, or secret functions.

## Consequences

Controls are inspectable and cannot execute scripts. Each expression is parsed
and type-checked before activation. Dynamic provider evidence needs thorough
contract tests because field mistakes cannot all be caught statically.

