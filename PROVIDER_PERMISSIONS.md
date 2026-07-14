# Provider permissions

Providers request only the operations used by their collectors. Run
`trisoc permissions explain --provider azure` or
`trisoc permissions explain --provider aws` to map every action to controls.
The deployable custom-role JSON is in
`deploy/bicep/azure-attestor-reader-role.json`.

- Microsoft: read workspace and query Logs; read Sentinel onboarding states,
  connectors, analytics rules, and automation rules.
- AWS: read caller identity and Organizations accounts; GuardDuty detectors and
  delegated administrator; Security Hub CSPM hub, standards, and delegated
  administrator; CloudTrail trails/status/selectors; Config recorder status;
  optional Security Lake data lakes; and optional OpenSearch domain security
  configuration. The deployable cross-account role is
  `deploy/cloudformation/aws-attestor-assessment-role.yaml`.
- Google: list/get organisation sinks and read organisation metadata.

Deployment permissions are separate from assessment permissions. The assessment
role's external ID must be supplied through a protected local credential source;
it is excluded from serialized targets. Omission of a required read permission
must produce `unknown` with the collection error, never a compliance failure.
