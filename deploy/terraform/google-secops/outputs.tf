output "chronicle_feed_name" {
  value       = google_chronicle_feed.cloud_audit.name
  description = "Fully qualified Google Security Operations feed resource name."
}

output "chronicle_feed_state" {
  value       = google_chronicle_feed.cloud_audit.state
  description = "Current feed state returned by Google Security Operations."
}

output "organization_log_sink_writer" {
  value       = google_logging_organization_sink.cloud_audit.writer_identity
  description = "Google-managed identity publishing organization audit logs."
}

output "pubsub_subscription" {
  value       = google_pubsub_subscription.cloud_audit_to_secops.id
  description = "Authenticated push subscription delivering logs to Google SecOps."
}
