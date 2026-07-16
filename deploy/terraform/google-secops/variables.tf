variable "project_id" {
  description = "Google Cloud project bound to the Google Security Operations instance."
  type        = string
}

variable "organization_id" {
  description = "Numeric Google Cloud organization ID whose child audit logs are routed."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must contain digits only."
  }
}

variable "gcp_region" {
  description = "Google Cloud region used for Pub/Sub message storage policy."
  type        = string
  default     = "australia-southeast1"
}

variable "chronicle_location" {
  description = "Location of the provisioned Google Security Operations instance."
  type        = string
  default     = "australia-southeast1"
}

variable "chronicle_instance_id" {
  description = "Provisioned Google Security Operations instance/customer UUID."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.chronicle_instance_id))
    error_message = "chronicle_instance_id must be a UUID."
  }
}

variable "feed_display_name" {
  description = "Display name for the Cloud Audit Logs feed."
  type        = string
  default     = "TriSOC organization Cloud Audit Logs"
}

variable "topic_name" {
  description = "Pub/Sub topic receiving aggregated organization audit logs."
  type        = string
  default     = "trisoc-google-secops-cloud-audit"
}

variable "labels" {
  description = "Labels applied to supported resources."
  type        = map(string)
  default = {
    managed-by          = "trisoc"
    data-classification = "security-telemetry"
  }
}
