# Guidance governance

Only official Microsoft, AWS, and Google domains are accepted by default. A
future synchroniser will use ETag, Last-Modified, and content hashes, retain every
snapshot, and open a review item when a source changes. It will not rewrite an
active control.

A human reviewer must compare old and new guidance, approve the interpretation,
increment the control version where semantics changed, and record identity and
rationale. LLM output can propose draft wording but is never authoritative.
Offline deployments will use a signed, pinned guidance bundle.

