# Threat model

## Assets and trust boundaries

Assets include cloud identities, configuration evidence, tenant metadata,
control interpretations, approval records, signing keys, generated IaC, and the
integrity of attestation history. Trust boundaries exist at every MCP/HTTP/CLI
input, provider API, guidance fetch, secret provider, database connection,
notification destination, and generated plan review.

## Principal threats and controls

| Threat | Initial controls | Required follow-up before exposure |
|---|---|---|
| Malicious control executes code | CEL-only evaluation; no process/network functions; strict YAML; aliases and custom tags rejected | Evaluator resource budgets and adversarial corpus |
| Prompt injection requests a cloud change | Current MCP tools are read-only; tool annotations state impact | Human-bound, expiring, replay-safe plan approval |
| Evidence contains a credential | Recursive key/value redaction before hash; no raw logs in MCP | Provider-specific redaction allow/deny tests and secret scanners |
| Collection error becomes a pass | Architectural invariant: typed collection errors map only to unknown/error | Provider contract and end-to-end tests |
| Tenant reads another tenant | Tenant ID on owned records; foreign keys | RLS, scoped repositories, negative integration tests |
| Historical evidence is altered | Database immutability triggers; future hash chains and signatures | KMS/Ed25519 key rotation and verification tooling |
| SSRF through guidance URLs | Official HTTPS hostname allowlist | Redirect revalidation, DNS/IP checks, response limits |
| Path traversal through MCP validation | Relative paths only; parent traversal rejected | Root-confined filesystem opening without symlink races |
| MCP denial of service | 1 MiB input cap, 200-control result cap, HTTP timeouts | Per-client rate limits and job quotas |
| Forged or replayed approval | No apply operation exists yet | Exact plan hash, identity, scope, expiry, nonce, atomic consumption |
| Supply-chain compromise | Pinned Go modules, minimal non-root container, CI scanning | Signed releases, provenance, SBOM, dependency update policy |

## Security invariants

1. Lack of evidence is never a pass.
2. An exception preserves the failed technical observation.
3. An LLM cannot approve its own change.
4. A changed plan invalidates approval.
5. Secrets are redacted before persistence, hashing, logging, or agent output.
6. High-impact and destructive remediation is never automatic.
7. Historical results are corrected only by appending new records.

## Residual risks in the foundation release

HTTP MCP has no native authentication and is suitable only on loopback. Control
validation accepts local paths beneath the process working directory but does
not yet use a directory file descriptor to eliminate every symlink race. The
database schema establishes tenant columns but row-level security is not yet
enabled, so this release is local-first and not approved for shared hosting.

