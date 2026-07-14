package azure

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Collector struct {
	api      API
	identity string
	clock    func() time.Time
}

func NewCollector(api API, identity string) *Collector {
	return &Collector{api: api, identity: identity, clock: func() time.Time { return time.Now().UTC() }}
}

func (c *Collector) Discover(ctx context.Context, target Target) (Snapshot, error) {
	if target.MinimumRetentionDays == 0 {
		target.MinimumRetentionDays = 90
	}
	if err := validateTarget(target); err != nil {
		return Snapshot{}, err
	}
	workspace, err := c.api.Workspace(ctx, target.ResourceGroup, target.WorkspaceName)
	if err != nil {
		return Snapshot{}, err
	}
	enabled, err := c.api.SentinelEnabled(ctx, target.ResourceGroup, target.WorkspaceName)
	if err != nil {
		return Snapshot{}, err
	}
	connectors, err := c.api.Connectors(ctx, target.ResourceGroup, target.WorkspaceName)
	if err != nil {
		return Snapshot{}, err
	}
	rules, err := c.api.AlertRules(ctx, target.ResourceGroup, target.WorkspaceName)
	if err != nil {
		return Snapshot{}, err
	}
	automation, err := c.api.AutomationRules(ctx, target.ResourceGroup, target.WorkspaceName)
	if err != nil {
		return Snapshot{}, err
	}
	health, err := c.api.Health(ctx, workspace.CustomerID)
	if err != nil {
		return Snapshot{}, err
	}
	telemetry, err := c.api.Telemetry(ctx, workspace.CustomerID, target.ExpectedTables)
	if err != nil {
		return Snapshot{}, err
	}
	present := requiredConnectorsPresent(connectors, target.RequiredConnectors)
	return Snapshot{Provider: "microsoft", SubscriptionID: target.SubscriptionID, ResourceGroup: target.ResourceGroup, WorkspaceName: workspace.Name, WorkspaceResourceID: workspace.ResourceID, WorkspaceID: workspace.CustomerID, Location: workspace.Location, ProvisioningState: workspace.ProvisioningState, SentinelEnabled: enabled, RetentionDays: workspace.RetentionDays, MinimumRetentionDays: target.MinimumRetentionDays, Connectors: connectors, RequiredConnectors: append([]string(nil), target.RequiredConnectors...), RequiredConnectorsPresent: present, RequiredConnectorsConfigured: len(target.RequiredConnectors) > 0, AlertRules: rules, AutomationRules: automation, Health: Health{MonitoringDataPresent: health.LastHealthEvent != nil, AuditDataPresent: health.LastAuditEvent != nil, LastHealthEvent: health.LastHealthEvent, LastAuditEvent: health.LastAuditEvent, ConnectorFailures: health.ConnectorFailures, AnalyticsRuleFailures: health.AnalyticsRuleFailures, AutomationFailures: health.AutomationFailures}, Telemetry: telemetry, TelemetryRequired: len(target.ExpectedTables) > 0, AutomationRequired: target.RequireAutomation, ObservedAt: c.clock(), CollectorIdentity: c.identity}, nil
}

func validateTarget(t Target) error {
	if strings.TrimSpace(t.SubscriptionID) == "" || strings.TrimSpace(t.ResourceGroup) == "" || strings.TrimSpace(t.WorkspaceName) == "" {
		return fmt.Errorf("subscription, resource group, and workspace are required")
	}
	if t.MinimumRetentionDays <= 0 {
		t.MinimumRetentionDays = 90
	}
	for _, table := range t.ExpectedTables {
		if !tableNamePattern.MatchString(table) {
			return fmt.Errorf("invalid expected table %q", table)
		}
	}
	return nil
}

func requiredConnectorsPresent(connectors []Connector, required []string) bool {
	for _, wanted := range required {
		found := false
		for _, connector := range connectors {
			if connector.Enabled && (strings.EqualFold(connector.Kind, wanted) || strings.EqualFold(connector.Name, wanted)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
