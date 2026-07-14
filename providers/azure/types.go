package azure

import "time"

type Target struct {
	SubscriptionID       string   `json:"subscriptionId" yaml:"subscriptionId"`
	ResourceGroup        string   `json:"resourceGroup" yaml:"resourceGroup"`
	WorkspaceName        string   `json:"workspaceName" yaml:"workspaceName"`
	MinimumRetentionDays int32    `json:"minimumRetentionDays" yaml:"minimumRetentionDays"`
	RequiredConnectors   []string `json:"requiredConnectors" yaml:"requiredConnectors"`
	ExpectedTables       []string `json:"expectedTables" yaml:"expectedTables"`
	RequireAutomation    bool     `json:"requireAutomation" yaml:"requireAutomation"`
}

type Snapshot struct {
	Provider                     string            `json:"provider" yaml:"provider"`
	SubscriptionID               string            `json:"subscriptionId" yaml:"subscriptionId"`
	ResourceGroup                string            `json:"resourceGroup" yaml:"resourceGroup"`
	WorkspaceName                string            `json:"workspaceName" yaml:"workspaceName"`
	WorkspaceResourceID          string            `json:"workspaceResourceId" yaml:"workspaceResourceId"`
	WorkspaceID                  string            `json:"workspaceId" yaml:"workspaceId"`
	Location                     string            `json:"location" yaml:"location"`
	ProvisioningState            string            `json:"provisioningState" yaml:"provisioningState"`
	SentinelEnabled              bool              `json:"sentinelEnabled" yaml:"sentinelEnabled"`
	RetentionDays                int32             `json:"retentionDays" yaml:"retentionDays"`
	MinimumRetentionDays         int32             `json:"minimumRetentionDays" yaml:"minimumRetentionDays"`
	Connectors                   []Connector       `json:"connectors" yaml:"connectors"`
	RequiredConnectors           []string          `json:"requiredConnectors" yaml:"requiredConnectors"`
	RequiredConnectorsPresent    bool              `json:"requiredConnectorsPresent" yaml:"requiredConnectorsPresent"`
	RequiredConnectorsConfigured bool              `json:"requiredConnectorsConfigured" yaml:"requiredConnectorsConfigured"`
	AlertRules                   []AlertRule       `json:"alertRules" yaml:"alertRules"`
	AutomationRules              []AutomationRule  `json:"automationRules" yaml:"automationRules"`
	Health                       Health            `json:"health" yaml:"health"`
	Telemetry                    []TelemetrySource `json:"telemetry" yaml:"telemetry"`
	TelemetryRequired            bool              `json:"telemetryRequired" yaml:"telemetryRequired"`
	AutomationRequired           bool              `json:"automationRequired" yaml:"automationRequired"`
	ObservedAt                   time.Time         `json:"observedAt" yaml:"observedAt"`
	CollectorIdentity            string            `json:"collectorIdentity" yaml:"collectorIdentity"`
}

type Workspace struct {
	ResourceID        string
	CustomerID        string
	Name              string
	ResourceGroup     string
	Location          string
	ProvisioningState string
	RetentionDays     int32
}

type Connector struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	Kind    string `json:"kind" yaml:"kind"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

type AlertRule struct {
	ID              string     `json:"id" yaml:"id"`
	Name            string     `json:"name" yaml:"name"`
	DisplayName     string     `json:"displayName" yaml:"displayName"`
	Kind            string     `json:"kind" yaml:"kind"`
	Enabled         bool       `json:"enabled" yaml:"enabled"`
	TemplateVersion string     `json:"templateVersion,omitempty" yaml:"templateVersion,omitempty"`
	LastModified    *time.Time `json:"lastModified,omitempty" yaml:"lastModified,omitempty"`
}

type AutomationRule struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	DisplayName string `json:"displayName" yaml:"displayName"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	ActionCount int    `json:"actionCount" yaml:"actionCount"`
}

type Health struct {
	MonitoringDataPresent bool       `json:"monitoringDataPresent" yaml:"monitoringDataPresent"`
	AuditDataPresent      bool       `json:"auditDataPresent" yaml:"auditDataPresent"`
	LastHealthEvent       *time.Time `json:"lastHealthEvent,omitempty" yaml:"lastHealthEvent,omitempty"`
	LastAuditEvent        *time.Time `json:"lastAuditEvent,omitempty" yaml:"lastAuditEvent,omitempty"`
	ConnectorFailures     int64      `json:"connectorFailures" yaml:"connectorFailures"`
	AnalyticsRuleFailures int64      `json:"analyticsRuleFailures" yaml:"analyticsRuleFailures"`
	AutomationFailures    int64      `json:"automationFailures" yaml:"automationFailures"`
}

type TelemetrySource struct {
	Table             string     `json:"table" yaml:"table"`
	LastEvent         *time.Time `json:"lastEvent,omitempty" yaml:"lastEvent,omitempty"`
	MaximumAgeMinutes int64      `json:"maximumAgeMinutes" yaml:"maximumAgeMinutes"`
	RecentEvents      int64      `json:"recentEvents" yaml:"recentEvents"`
	BaselineMedian    float64    `json:"baselineMedian" yaml:"baselineMedian"`
	DropPercent       float64    `json:"dropPercent" yaml:"dropPercent"`
	IncreasePercent   float64    `json:"increasePercent" yaml:"increasePercent"`
	Healthy           bool       `json:"healthy" yaml:"healthy"`
}

type RawHealth struct {
	LastHealthEvent, LastAuditEvent                              *time.Time
	ConnectorFailures, AnalyticsRuleFailures, AutomationFailures int64
}
