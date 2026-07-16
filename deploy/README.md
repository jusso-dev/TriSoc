# Deployment assets

Ready-to-deploy, plan-first SIEM baselines are included for:

- Microsoft Sentinel in `bicep/microsoft-sentinel`.
- AWS-native security operations in
  `cloudformation/aws-security-operations-baseline.yaml`.
- Google Security Operations in `terraform/google-secops`.

Splunk is checked for log-source compliance and CIM normalisation, but Splunk
deployment IaC is intentionally out of scope. See [the deployment guide](../docs/SIEM_IAC.md)
for prerequisites, safe rollout commands, and platform caveats.

After deployment and connector onboarding, require the combined log-source and
SOC-CMM gate documented in [the maturity guide](../docs/SOC_MATURITY.md).
