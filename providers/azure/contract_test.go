package azure

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"
	"github.com/trisoc/attestor/internal/attestation"
	"github.com/trisoc/attestor/internal/control"
)

type fixture struct {
	Workspace       Workspace         `json:"workspace"`
	SentinelEnabled bool              `json:"sentinelEnabled"`
	Connectors      []Connector       `json:"connectors"`
	AlertRules      []AlertRule       `json:"alertRules"`
	AutomationRules []AutomationRule  `json:"automationRules"`
	Health          RawHealth         `json:"health"`
	Telemetry       []TelemetrySource `json:"telemetry"`
}
type fixtureAPI struct {
	fixture fixture
	err     error
}

func (f fixtureAPI) Workspace(context.Context, string, string) (Workspace, error) {
	return f.fixture.Workspace, f.err
}
func (f fixtureAPI) SentinelEnabled(context.Context, string, string) (bool, error) {
	return f.fixture.SentinelEnabled, f.err
}
func (f fixtureAPI) Connectors(context.Context, string, string) ([]Connector, error) {
	return f.fixture.Connectors, f.err
}
func (f fixtureAPI) AlertRules(context.Context, string, string) ([]AlertRule, error) {
	return f.fixture.AlertRules, f.err
}
func (f fixtureAPI) AutomationRules(context.Context, string, string) ([]AutomationRule, error) {
	return f.fixture.AutomationRules, f.err
}
func (f fixtureAPI) Health(context.Context, string) (RawHealth, error) {
	return f.fixture.Health, f.err
}
func (f fixtureAPI) Telemetry(context.Context, string, []string) ([]TelemetrySource, error) {
	return f.fixture.Telemetry, f.err
}

func TestSanitisedFixturePassesMicrosoftControlPack(t *testing.T) {
	fx := loadFixture(t)
	collector := NewCollector(fixtureAPI{fixture: fx}, "test-collector")
	collector.clock = func() time.Time { return time.Date(2026, 7, 14, 0, 30, 0, 0, time.UTC) }
	snapshot, err := collector.Discover(context.Background(), Target{SubscriptionID: "00000000-0000-0000-0000-000000000000", ResourceGroup: "security", WorkspaceName: "soc-prod", MinimumRetentionDays: 90, RequiredConnectors: []string{"AzureActiveDirectory", "AzureActivity"}, ExpectedTables: []string{"SigninLogs", "AzureActivity"}, RequireAutomation: true})
	if err != nil {
		t.Fatal(err)
	}
	store, result := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !result.Valid {
		t.Fatal(result.Issues)
	}
	evaluator, err := attestation.New("test")
	if err != nil {
		t.Fatal(err)
	}
	controls := store.LatestByVendor("microsoft")
	if len(controls) != 10 {
		t.Fatalf("controls=%d, want 10", len(controls))
	}
	for _, c := range controls {
		got, err := evaluator.Evaluate(c, snapshot, snapshot.ObservedAt)
		if err != nil {
			t.Fatalf("%s: %v", c.Metadata.ID, err)
		}
		if got.Result != "pass" {
			t.Errorf("%s=%s, want pass", c.Metadata.ID, got.Result)
		}
	}
}

func TestMissingConnectorFailsDeterministically(t *testing.T) {
	fx := loadFixture(t)
	snapshot, err := NewCollector(fixtureAPI{fixture: fx}, "test").Discover(context.Background(), Target{SubscriptionID: "sub", ResourceGroup: "security", WorkspaceName: "soc-prod", MinimumRetentionDays: 90, RequiredConnectors: []string{"MicrosoftDefenderForEndpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RequiredConnectorsPresent {
		t.Fatal("missing connector marked present")
	}
}

func TestRejectsKQLTableInjection(t *testing.T) {
	fx := loadFixture(t)
	_, err := NewCollector(fixtureAPI{fixture: fx}, "test").Discover(context.Background(), Target{SubscriptionID: "sub", ResourceGroup: "rg", WorkspaceName: "ws", ExpectedTables: []string{"SigninLogs | take 1"}})
	if err == nil {
		t.Fatal("malicious table name accepted")
	}
}

func TestBicepPlanIsReviewableAndCredentialFree(t *testing.T) {
	plan, err := GenerateBicepPlan(Target{ResourceGroup: "security", WorkspaceName: "soc-prod", MinimumRetentionDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Microsoft.SecurityInsights/onboardingStates@2024-09-01", "retentionInDays", "targetScope"} {
		if !strings.Contains(plan.Source, required) {
			t.Errorf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"password", "clientSecret", "accessToken"} {
		if strings.Contains(plan.Source, forbidden) {
			t.Errorf("plan contains %q", forbidden)
		}
	}
}

func TestPermissionBundleContainsOnlyReadAndQuery(t *testing.T) {
	raw, err := ReadOnlyRoleJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/write") || strings.Contains(string(raw), "/delete") || strings.Contains(string(raw), "/action") {
		t.Fatalf("write permission in bundle: %s", raw)
	}
}

func TestRecordedConnectorResponseNormalisation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "azure", "data_connectors_response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var response armsecurityinsights.DataConnectorList
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Value) != 2 {
		t.Fatalf("connectors=%d", len(response.Value))
	}
	enabled := normaliseConnector(response.Value[0])
	disabled := normaliseConnector(response.Value[1])
	if !enabled.Enabled || disabled.Enabled {
		t.Fatalf("normalisation enabled=%v disabled=%v", enabled.Enabled, disabled.Enabled)
	}
}

func TestPermissionDenialIsNotPartialSuccess(t *testing.T) {
	fx := loadFixture(t)
	_, err := NewCollector(fixtureAPI{fixture: fx, err: assertionError("authorization failed")}, "test").Discover(context.Background(), Target{SubscriptionID: "sub", ResourceGroup: "rg", WorkspaceName: "ws"})
	if err == nil || !strings.Contains(err.Error(), "authorization failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }

func loadFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "azure", "sentinel_workspace.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return fx
}
