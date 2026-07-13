# Remediation safety

The foundation release cannot apply remediation. Future execution must satisfy
all of these gates:

1. Fresh evidence and a reviewable, content-addressed plan.
2. Pre-checks, affected resources, permission needs, cost class, interruption,
   rollback, and validation shown before approval.
3. An authenticated human approval bound to the exact plan hash and scope.
4. Explicit CLI `--apply` plus confirmation, or an independently approved plan
   ID for MCP. An agent request is not approval.
5. Least-privilege deployment identity and atomic approval-token consumption.
6. Audit events for approval and every apply step.
7. Targeted post-change attestation.

Destructive changes, retention reductions, organisation-wide IAM changes, log
archive replacement, KMS policy changes, security-service disablement, and broad
high-cost logging are never automatic.

