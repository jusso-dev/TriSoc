locals {
  required_services = toset([
    "chronicle.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
  ])
  chronicle_endpoint = "chronicle.${lower(var.chronicle_location)}.rep.googleapis.com"
  log_type = format(
    "projects/%s/locations/%s/instances/%s/logTypes/GCP_CLOUDAUDIT",
    var.project_id,
    var.chronicle_location,
    var.chronicle_instance_id,
  )
}

resource "google_project_service" "required" {
  for_each = local.required_services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"

  depends_on = [google_project_service.required]
}

// Enable Admin Read, Data Read, and Data Write audit logs at organization
// scope so the aggregated sink cannot silently omit data-access activity.
resource "google_organization_iam_audit_config" "all_services" {
  org_id  = var.organization_id
  service = "allServices"

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }

  depends_on = [google_project_service.required]
}

resource "google_pubsub_topic" "cloud_audit" {
  project = var.project_id
  name    = var.topic_name
  labels  = var.labels

  message_storage_policy {
    allowed_persistence_regions = [var.gcp_region]
  }

  depends_on = [google_project_service.required]
}

resource "google_logging_organization_sink" "cloud_audit" {
  name             = "trisoc-google-secops-cloud-audit"
  org_id           = var.organization_id
  destination      = "pubsub.googleapis.com/${google_pubsub_topic.cloud_audit.id}"
  include_children = true
  filter = join(" OR ", [
    "log_id(\"cloudaudit.googleapis.com/activity\")",
    "log_id(\"cloudaudit.googleapis.com/data_access\")",
    "log_id(\"cloudaudit.googleapis.com/system_event\")",
    "log_id(\"cloudaudit.googleapis.com/policy\")",
  ])
}

resource "google_pubsub_topic_iam_member" "log_sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.cloud_audit.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_organization_sink.cloud_audit.writer_identity
}

resource "google_service_account" "secops_push" {
  project      = var.project_id
  account_id   = "trisoc-secops-push"
  display_name = "TriSOC Google SecOps Pub/Sub push"
  description  = "OIDC identity used only by Pub/Sub to push organization audit logs to Google SecOps."

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "secops_push" {
  project = var.project_id
  role    = "roles/chronicle.editor"
  member  = "serviceAccount:${google_service_account.secops_push.email}"
}

resource "google_service_account_iam_member" "pubsub_mints_push_tokens" {
  service_account_id = google_service_account.secops_push.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

resource "google_chronicle_feed" "cloud_audit" {
  provider = google-beta

  project         = var.project_id
  location        = var.chronicle_location
  instance        = var.chronicle_instance_id
  display_name    = var.feed_display_name
  enabled         = true
  deletion_policy = "PREVENT"

  details {
    feed_source_type = "HTTPS_PUSH_GOOGLE_CLOUD_PUBSUB"
    log_type         = local.log_type

    https_push_google_cloud_pubsub_settings {
      split_delimiter = "\n"
    }
  }

  depends_on = [google_project_service.required]
}

locals {
  feed_id       = element(split("/", google_chronicle_feed.cloud_audit.name), 7)
  push_endpoint = "https://${local.chronicle_endpoint}/v1alpha/projects/${var.project_id}/locations/${var.chronicle_location}/instances/${var.chronicle_instance_id}/feeds/${local.feed_id}:importPushLogs"
}

resource "google_pubsub_subscription" "cloud_audit_to_secops" {
  project = var.project_id
  name    = "${var.topic_name}-push"
  topic   = google_pubsub_topic.cloud_audit.id
  labels  = var.labels

  ack_deadline_seconds       = 600
  message_retention_duration = "604800s"
  retain_acked_messages      = false

  expiration_policy {
    ttl = ""
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  push_config {
    push_endpoint = local.push_endpoint

    oidc_token {
      service_account_email = google_service_account.secops_push.email
      audience              = local.push_endpoint
    }
  }

  depends_on = [
    google_chronicle_feed.cloud_audit,
    google_project_iam_member.secops_push,
    google_pubsub_topic_iam_member.log_sink_publisher,
    google_service_account_iam_member.pubsub_mints_push_tokens,
  ]
}
