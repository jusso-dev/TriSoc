BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organisations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  display_name text NOT NULL,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organisation_id, user_id)
);

CREATE TABLE environments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  name text NOT NULL,
  environment_type text NOT NULL,
  timezone text NOT NULL DEFAULT 'UTC',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organisation_id, name)
);

CREATE TABLE cloud_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  provider text NOT NULL CHECK (provider IN ('microsoft','aws','google')),
  authentication_type text NOT NULL,
  secret_reference text,
  configuration jsonb NOT NULL DEFAULT '{}',
  last_validated_at timestamptz,
  credential_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cloud_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid NOT NULL REFERENCES cloud_connections(id),
  provider_scope_id text NOT NULL,
  scope_type text NOT NULL,
  display_name text NOT NULL,
  accessible boolean NOT NULL DEFAULT false,
  metadata jsonb NOT NULL DEFAULT '{}',
  discovered_at timestamptz NOT NULL,
  UNIQUE (connection_id, provider_scope_id)
);

CREATE TABLE resources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  cloud_scope_id uuid REFERENCES cloud_scopes(id),
  provider_resource_id text NOT NULL,
  resource_type text NOT NULL,
  region text,
  normalised_configuration jsonb NOT NULL,
  configuration_hash text NOT NULL CHECK (configuration_hash ~ '^sha256:[a-f0-9]{64}$'),
  observed_at timestamptz NOT NULL,
  UNIQUE (environment_id, provider_resource_id)
);

CREATE TABLE controls (
  id text PRIMARY KEY,
  vendor text NOT NULL CHECK (vendor IN ('microsoft','aws','google')),
  product text NOT NULL,
  service text NOT NULL,
  title text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id text NOT NULL REFERENCES controls(id),
  version text NOT NULL,
  status text NOT NULL CHECK (status IN ('draft','active','deprecated','superseded','disabled_by_organisation_policy')),
  definition jsonb NOT NULL,
  definition_hash text NOT NULL CHECK (definition_hash ~ '^sha256:[a-f0-9]{64}$'),
  evaluator_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (control_id, version)
);

CREATE TABLE control_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  control_version_id uuid NOT NULL REFERENCES control_versions(id),
  title text NOT NULL,
  source_url text NOT NULL,
  vendor_control_id text,
  retrieved_at timestamptz NOT NULL,
  published_at timestamptz,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[a-f0-9]{64}$'),
  UNIQUE (control_version_id, source_url)
);

CREATE TABLE baselines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid REFERENCES environments(id),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organisation_id, name)
);

CREATE TABLE baseline_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  baseline_id uuid NOT NULL REFERENCES baselines(id),
  version integer NOT NULL CHECK (version > 0),
  definition jsonb NOT NULL,
  definition_hash text NOT NULL CHECK (definition_hash ~ '^sha256:[a-f0-9]{64}$'),
  approved_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (baseline_id, version)
);

CREATE TABLE assessment_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  baseline_version_id uuid REFERENCES baseline_versions(id),
  kind text NOT NULL,
  status text NOT NULL CHECK (status IN ('queued','running','completed','cancelled','error')),
  requested_by uuid REFERENCES users(id),
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id),
  provider text NOT NULL CHECK (provider IN ('microsoft','aws','google')),
  scope_id uuid REFERENCES cloud_scopes(id),
  status text NOT NULL CHECK (status IN ('queued','running','completed','cancelled','error')),
  attempts integer NOT NULL DEFAULT 0,
  error_code text,
  error_detail text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id),
  provider text NOT NULL,
  operation text NOT NULL,
  scope text NOT NULL,
  resource_ids jsonb NOT NULL DEFAULT '[]',
  redacted_evidence jsonb NOT NULL,
  evidence_hash text NOT NULL CHECK (evidence_hash ~ '^sha256:[a-f0-9]{64}$'),
  collector_identity text NOT NULL,
  observed_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id),
  control_version_id uuid NOT NULL REFERENCES control_versions(id),
  evidence_record_id uuid REFERENCES evidence_records(id),
  result text NOT NULL CHECK (result IN ('pass','fail','warning','not_applicable','unknown','error','accepted_exception')),
  technical_observation text NOT NULL,
  technical_explanation text NOT NULL,
  plain_english_explanation text NOT NULL,
  observed_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (assessment_run_id, control_version_id)
);

CREATE TABLE attestation_bundles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  assessment_run_id uuid NOT NULL UNIQUE REFERENCES assessment_runs(id),
  previous_bundle_hash text,
  bundle_hash text NOT NULL UNIQUE CHECK (bundle_hash ~ '^sha256:[a-f0-9]{64}$'),
  signature_algorithm text NOT NULL,
  signing_key_id text NOT NULL,
  signature bytea NOT NULL,
  bundle jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE drift_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  control_result_id uuid REFERENCES control_results(id),
  drift_type text NOT NULL,
  previous_state jsonb,
  current_state jsonb NOT NULL,
  detected_at timestamptz NOT NULL,
  resolved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  control_id text NOT NULL REFERENCES controls(id),
  latest_result_id uuid NOT NULL REFERENCES control_results(id),
  status text NOT NULL CHECK (status IN ('open','accepted_exception','remediated','closed')),
  severity text NOT NULL,
  owner_id uuid REFERENCES users(id),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  UNIQUE (environment_id, control_id)
);

CREATE TABLE finding_comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  finding_id uuid NOT NULL REFERENCES findings(id),
  author_id uuid NOT NULL REFERENCES users(id),
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE telemetry_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  provider text NOT NULL,
  source_type text NOT NULL,
  source_identifier text NOT NULL,
  expected boolean NOT NULL DEFAULT true,
  configuration jsonb NOT NULL DEFAULT '{}',
  UNIQUE (environment_id, provider, source_identifier)
);

CREATE TABLE telemetry_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  telemetry_source_id uuid NOT NULL REFERENCES telemetry_sources(id),
  observed_at timestamptz NOT NULL,
  last_event_at timestamptz,
  event_count bigint,
  byte_count bigint,
  normalisation_percent numeric(5,2),
  required_field_percent numeric(5,2),
  status text NOT NULL,
  evidence_hash text NOT NULL,
  UNIQUE (telemetry_source_id, observed_at)
);

CREATE TABLE detection_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  provider text NOT NULL,
  provider_rule_id text NOT NULL,
  title text NOT NULL,
  owner_id uuid REFERENCES users(id),
  UNIQUE (environment_id, provider_rule_id)
);

CREATE TABLE detection_rule_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  detection_rule_id uuid NOT NULL REFERENCES detection_rules(id),
  version text NOT NULL,
  approved boolean NOT NULL DEFAULT false,
  definition jsonb NOT NULL,
  definition_hash text NOT NULL,
  observed_at timestamptz NOT NULL,
  UNIQUE (detection_rule_id, version)
);

CREATE TABLE detection_coverage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id),
  detection_rule_id uuid REFERENCES detection_rules(id),
  technique_id text NOT NULL,
  telemetry_present boolean,
  rule_enabled boolean,
  rule_healthy boolean,
  last_executed_at timestamptz,
  observation jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  finding_id uuid NOT NULL REFERENCES findings(id),
  status text NOT NULL CHECK (status IN ('draft','validated','pending_approval','approved','applying','applied','verified','failed','rolled_back','rejected')),
  risk text NOT NULL,
  destructive boolean NOT NULL DEFAULT false,
  reversible boolean NOT NULL,
  plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
  plan jsonb NOT NULL,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_plan_steps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  remediation_plan_id uuid NOT NULL REFERENCES remediation_plans(id),
  sequence integer NOT NULL CHECK (sequence > 0),
  action_type text NOT NULL,
  proposed_change jsonb NOT NULL,
  rollback jsonb NOT NULL,
  validation jsonb NOT NULL,
  UNIQUE (remediation_plan_id, sequence)
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  remediation_plan_id uuid NOT NULL REFERENCES remediation_plans(id),
  plan_hash text NOT NULL,
  approver_id uuid NOT NULL REFERENCES users(id),
  decision text NOT NULL CHECK (decision IN ('approved','rejected','revoked')),
  approval_token_id text UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE exceptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  control_id text NOT NULL REFERENCES controls(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  scope jsonb NOT NULL,
  reason text NOT NULL,
  business_owner_id uuid NOT NULL REFERENCES users(id),
  compensating_controls text NOT NULL,
  supporting_evidence jsonb NOT NULL DEFAULT '[]',
  review_frequency interval NOT NULL,
  status text NOT NULL CHECK (status IN ('requested','approved','rejected','expired','revoked')),
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > starts_at),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE exception_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  exception_id uuid NOT NULL REFERENCES exceptions(id),
  approver_id uuid NOT NULL REFERENCES users(id),
  decision text NOT NULL CHECK (decision IN ('approved','rejected','revoked')),
  rationale text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE guidance_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_url text NOT NULL,
  retrieved_at timestamptz NOT NULL,
  etag text,
  last_modified text,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[a-f0-9]{64}$'),
  metadata jsonb NOT NULL,
  review_status text NOT NULL CHECK (review_status IN ('current','changed','reviewed','rejected')),
  reviewed_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_url, content_hash)
);

CREATE TABLE notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  channel text NOT NULL,
  deduplication_key text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL,
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX notifications_active_dedupe ON notifications (organisation_id, channel, deduplication_key) WHERE status IN ('queued','sent');

CREATE TABLE schedules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid REFERENCES environments(id),
  cron_expression text NOT NULL,
  timezone text NOT NULL,
  job_type text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  next_run_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text NOT NULL,
  request_id text,
  source_ip inet,
  details jsonb NOT NULL DEFAULT '{}',
  previous_event_hash text,
  event_hash text NOT NULL UNIQUE CHECK (event_hash ~ '^sha256:[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE signing_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid REFERENCES organisations(id),
  key_reference text NOT NULL,
  algorithm text NOT NULL,
  public_key bytea NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);

CREATE TABLE integration_health (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  environment_id uuid NOT NULL REFERENCES environments(id),
  integration_type text NOT NULL,
  integration_id text NOT NULL,
  status text NOT NULL,
  observation jsonb NOT NULL,
  observed_at timestamptz NOT NULL,
  UNIQUE (environment_id, integration_type, integration_id, observed_at)
);

CREATE INDEX assessment_runs_environment_created_idx ON assessment_runs (environment_id, created_at DESC);
CREATE INDEX control_results_control_observed_idx ON control_results (control_version_id, observed_at DESC);
CREATE INDEX drift_events_environment_detected_idx ON drift_events (environment_id, detected_at DESC);
CREATE INDEX findings_org_status_severity_idx ON findings (organisation_id, status, severity);
CREATE INDEX telemetry_observations_source_observed_idx ON telemetry_observations (telemetry_source_id, observed_at DESC);
CREATE INDEX audit_events_org_occurred_idx ON audit_events (organisation_id, occurred_at DESC);

CREATE FUNCTION reject_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'historical attestation and audit records are immutable';
END;
$$;

CREATE TRIGGER evidence_records_immutable BEFORE UPDATE OR DELETE ON evidence_records FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER control_results_immutable BEFORE UPDATE OR DELETE ON control_results FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER attestation_bundles_immutable BEFORE UPDATE OR DELETE ON attestation_bundles FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER approvals_immutable BEFORE UPDATE OR DELETE ON approvals FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER exception_approvals_immutable BEFORE UPDATE OR DELETE ON exception_approvals FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

COMMIT;

