# Provider permissions

The foundation release does not yet request cloud permissions. The three example
controls declare their anticipated read operations so permission bundles can be
generated from collector requirements rather than a manually maintained broad
role.

- Microsoft: read workspace, Sentinel operations, and diagnostic settings.
- AWS: describe trails, event selectors, trail status, and the organisation.
- Google: list/get organisation sinks and read organisation metadata.

Phase-specific collectors will ship versioned Azure custom roles, AWS IAM and
StackSet templates, and Google custom roles. Deployment permissions will be
separate from assessment permissions. Omission must produce `unknown` with the
missing permission, never a compliance failure.

