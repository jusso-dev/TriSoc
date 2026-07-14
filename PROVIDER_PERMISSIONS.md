# Provider permissions

The Microsoft provider now requests only the operations used by its collectors.
Run `trisoc permissions explain --provider azure` to map every action to controls.
The deployable custom-role JSON is in
`deploy/bicep/azure-attestor-reader-role.json`.

- Microsoft: read workspace and query Logs; read Sentinel onboarding states,
  connectors, analytics rules, and automation rules.
- AWS: describe trails, event selectors, trail status, and the organisation.
- Google: list/get organisation sinks and read organisation metadata.

Phase-specific collectors will ship versioned Azure custom roles, AWS IAM and
StackSet templates, and Google custom roles. Deployment permissions will be
separate from assessment permissions. Omission must produce `unknown` with the
missing permission, never a compliance failure.
