BEGIN;
DROP TABLE IF EXISTS integration_health, signing_keys, audit_events, schedules, notifications, guidance_snapshots, exception_approvals, exceptions, approvals, remediation_plan_steps, remediation_plans, detection_coverage, detection_rule_versions, detection_rules, telemetry_observations, telemetry_sources, finding_comments, findings, drift_events, attestation_bundles, control_results, evidence_records, assessment_jobs, assessment_runs, baseline_versions, baselines, control_sources, control_versions, controls, resources, cloud_scopes, cloud_connections, environments, memberships, users, organisations CASCADE;
DROP FUNCTION IF EXISTS reject_immutable_change();
COMMIT;
