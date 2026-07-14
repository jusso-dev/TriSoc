package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"
)

type API interface {
	Workspace(context.Context, string, string) (Workspace, error)
	SentinelEnabled(context.Context, string, string) (bool, error)
	Connectors(context.Context, string, string) ([]Connector, error)
	AlertRules(context.Context, string, string) ([]AlertRule, error)
	AutomationRules(context.Context, string, string) ([]AutomationRule, error)
	Health(context.Context, string) (RawHealth, error)
	Telemetry(context.Context, string, []string) ([]TelemetrySource, error)
}

type sdkAPI struct {
	workspaces *armoperationalinsights.WorkspacesClient
	onboarding *armsecurityinsights.SentinelOnboardingStatesClient
	connectors *armsecurityinsights.DataConnectorsClient
	alerts     *armsecurityinsights.AlertRulesClient
	automation *armsecurityinsights.AutomationRulesClient
	logs       *azquery.LogsClient
}

const maxDiscoveredResources = 5000

func NewDefaultAPI(subscriptionID string) (API, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure default credential: %w", err)
	}
	return NewAPI(subscriptionID, credential)
}

func NewAPI(subscriptionID string, credential azcore.TokenCredential) (API, error) {
	if subscriptionID == "" {
		return nil, fmt.Errorf("subscription ID is required")
	}
	workspaces, err := armoperationalinsights.NewWorkspacesClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}
	onboarding, err := armsecurityinsights.NewSentinelOnboardingStatesClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}
	connectors, err := armsecurityinsights.NewDataConnectorsClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}
	alerts, err := armsecurityinsights.NewAlertRulesClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}
	automation, err := armsecurityinsights.NewAutomationRulesClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}
	logs, err := azquery.NewLogsClient(credential, nil)
	if err != nil {
		return nil, err
	}
	return &sdkAPI{workspaces: workspaces, onboarding: onboarding, connectors: connectors, alerts: alerts, automation: automation, logs: logs}, nil
}

func (a *sdkAPI) Workspace(ctx context.Context, resourceGroup, name string) (Workspace, error) {
	response, err := a.workspaces.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return Workspace{}, classify("workspaces.get", err)
	}
	w := response.Workspace
	out := Workspace{Name: name, ResourceGroup: resourceGroup}
	if w.ID != nil {
		out.ResourceID = *w.ID
	}
	if w.Name != nil {
		out.Name = *w.Name
	}
	if w.Location != nil {
		out.Location = *w.Location
	}
	if w.Properties != nil {
		if w.Properties.CustomerID != nil {
			out.CustomerID = *w.Properties.CustomerID
		}
		if w.Properties.RetentionInDays != nil {
			out.RetentionDays = *w.Properties.RetentionInDays
		}
		if w.Properties.ProvisioningState != nil {
			out.ProvisioningState = string(*w.Properties.ProvisioningState)
		}
	}
	return out, nil
}

func (a *sdkAPI) SentinelEnabled(ctx context.Context, resourceGroup, workspace string) (bool, error) {
	response, err := a.onboarding.List(ctx, resourceGroup, workspace, nil)
	if err != nil {
		return false, classify("sentinel.onboardingStates.list", err)
	}
	return len(response.Value) > 0, nil
}

func (a *sdkAPI) Connectors(ctx context.Context, resourceGroup, workspace string) ([]Connector, error) {
	pager := a.connectors.NewListPager(resourceGroup, workspace, nil)
	var out []Connector
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classify("sentinel.dataConnectors.list", err)
		}
		for _, item := range page.Value {
			out = append(out, normaliseConnector(item))
			if len(out) > maxDiscoveredResources {
				return nil, fmt.Errorf("Sentinel connector result exceeds %d item safety limit", maxDiscoveredResources)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (a *sdkAPI) AlertRules(ctx context.Context, resourceGroup, workspace string) ([]AlertRule, error) {
	pager := a.alerts.NewListPager(resourceGroup, workspace, nil)
	var out []AlertRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classify("sentinel.alertRules.list", err)
		}
		for _, item := range page.Value {
			out = append(out, normaliseAlertRule(item))
			if len(out) > maxDiscoveredResources {
				return nil, fmt.Errorf("Sentinel alert rule result exceeds %d item safety limit", maxDiscoveredResources)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (a *sdkAPI) AutomationRules(ctx context.Context, resourceGroup, workspace string) ([]AutomationRule, error) {
	pager := a.automation.NewListPager(resourceGroup, workspace, nil)
	var out []AutomationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classify("sentinel.automationRules.list", err)
		}
		for _, item := range page.Value {
			r := AutomationRule{}
			if item.ID != nil {
				r.ID = *item.ID
			}
			if item.Name != nil {
				r.Name = *item.Name
			}
			if item.Properties != nil {
				if item.Properties.DisplayName != nil {
					r.DisplayName = *item.Properties.DisplayName
				}
				r.ActionCount = len(item.Properties.Actions)
				if item.Properties.TriggeringLogic != nil && item.Properties.TriggeringLogic.IsEnabled != nil {
					r.Enabled = *item.Properties.TriggeringLogic.IsEnabled
				}
			}
			out = append(out, r)
			if len(out) > maxDiscoveredResources {
				return nil, fmt.Errorf("Sentinel automation rule result exceeds %d item safety limit", maxDiscoveredResources)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (a *sdkAPI) Health(ctx context.Context, workspaceID string) (RawHealth, error) {
	query := `let h=_SentinelHealth() | where TimeGenerated > ago(24h); union (h | summarize Last=max(TimeGenerated), ConnectorFailures=countif(Status != "Success" and SentinelResourceType == "Data connector"), AnalyticsFailures=countif(Status != "Success" and SentinelResourceType == "Analytics rule"), AutomationFailures=countif(Status != "Success" and SentinelResourceType in ("Automation rule","Playbook")) | extend Kind="health"), (_SentinelAudit() | where TimeGenerated > ago(24h) | summarize Last=max(TimeGenerated) | extend ConnectorFailures=long(0), AnalyticsFailures=long(0), AutomationFailures=long(0), Kind="audit")`
	result, err := a.logs.QueryWorkspace(ctx, workspaceID, azquery.Body{Query: &query}, nil)
	if err != nil {
		return RawHealth{}, classify("logAnalytics.health.query", err)
	}
	return parseHealth(result.Tables), nil
}

var tableNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)

func (a *sdkAPI) Telemetry(ctx context.Context, workspaceID string, tables []string) ([]TelemetrySource, error) {
	if len(tables) == 0 {
		return []TelemetrySource{}, nil
	}
	parts := make([]string, 0, len(tables))
	for _, table := range tables {
		if !tableNamePattern.MatchString(table) {
			return nil, fmt.Errorf("invalid Log Analytics table name %q", table)
		}
		parts = append(parts, fmt.Sprintf(`(%s | where TimeGenerated > ago(14d) | summarize LastEvent=max(TimeGenerated), Recent=countif(TimeGenerated > ago(1h)), Baseline=countif(TimeGenerated between (ago(8d)..ago(7d))) | extend TableName="%s")`, table, table))
	}
	query := "union isfuzzy=true " + strings.Join(parts, ",")
	result, err := a.logs.QueryWorkspace(ctx, workspaceID, azquery.Body{Query: &query}, nil)
	if err != nil {
		return nil, classify("logAnalytics.telemetry.query", err)
	}
	return parseTelemetry(result.Tables, time.Now().UTC()), nil
}

func containsEnabledState(raw []byte) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, item := range t {
				if strings.EqualFold(k, "state") {
					if state, ok := item.(string); ok && strings.EqualFold(state, "Enabled") {
						return true
					}
				}
				if walk(item) {
					return true
				}
			}
		case []any:
			for _, item := range t {
				if walk(item) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func normaliseConnector(item armsecurityinsights.DataConnectorClassification) Connector {
	base := item.GetDataConnector()
	c := Connector{}
	if base.ID != nil {
		c.ID = *base.ID
	}
	if base.Name != nil {
		c.Name = *base.Name
	}
	if base.Kind != nil {
		c.Kind = string(*base.Kind)
	}
	raw, _ := json.Marshal(item)
	c.Enabled = containsEnabledState(raw)
	return c
}
func normaliseAlertRule(item armsecurityinsights.AlertRuleClassification) AlertRule {
	base := item.GetAlertRule()
	r := AlertRule{}
	if base.ID != nil {
		r.ID = *base.ID
	}
	if base.Name != nil {
		r.Name = *base.Name
	}
	if base.Kind != nil {
		r.Kind = string(*base.Kind)
	}
	raw, _ := json.Marshal(item)
	var doc struct {
		Properties struct {
			Enabled         *bool      `json:"enabled"`
			DisplayName     *string    `json:"displayName"`
			TemplateVersion *string    `json:"templateVersion"`
			LastModified    *time.Time `json:"lastModifiedUtc"`
		} `json:"properties"`
	}
	_ = json.Unmarshal(raw, &doc)
	if doc.Properties.Enabled != nil {
		r.Enabled = *doc.Properties.Enabled
	}
	if doc.Properties.DisplayName != nil {
		r.DisplayName = *doc.Properties.DisplayName
	}
	if doc.Properties.TemplateVersion != nil {
		r.TemplateVersion = *doc.Properties.TemplateVersion
	}
	r.LastModified = doc.Properties.LastModified
	return r
}

func classify(operation string, err error) error {
	return fmt.Errorf("Azure operation %s: %w", operation, err)
}

func ptrString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
func ptrInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}
