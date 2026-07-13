# Control authoring

Controls live under their provider pack and use
`attestor.trisoc.io/v1`. Start from an existing reviewed control, then run
`trisoc controls validate <file>`.

## Review checklist

1. Quote no recommendation from memory. Link an official allowlisted source and
   record its retrieval timestamp and SHA-256 content hash.
2. Preserve the vendor's product and service model. Use one of the five explicit
   classifications when guidance is optional or architectural.
3. List the exact read permissions and the bounded collector operation.
4. Express only deterministic boolean evaluation in CEL. Control data cannot run
   code, access the network, or read files.
5. State current/expected impact in technical and plain language. Avoid generic
   “best practice” claims.
6. List required evidence fields and secret-bearing paths. Set maximum evidence
   age based on operational risk.
7. Explain cost and remediation risk. Destructive actions cannot be marked for
   automatic apply.
8. Increment semantic versions for any interpretation or evaluation change.
   Historical attestations remain tied to the previous version.

The JSON Schema is `controls/schema/control.schema.json`; the Go validator is
canonical because it also compiles CEL and enforces source-domain policy.

