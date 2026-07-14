package aws

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/trisoc/attestor/internal/attestation"
	"github.com/trisoc/attestor/internal/control"
)

type fixtureAPI struct {
	snapshot Snapshot
	err      error
}

func (f fixtureAPI) Discover(context.Context, Target) (Snapshot, error) { return f.snapshot, f.err }

func TestSanitisedFixturePassesAWSControlPack(t *testing.T) {
	snapshot := loadSnapshot(t)
	collector := NewCollector(fixtureAPI{snapshot: snapshot})
	collector.clock = func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) }
	got, err := collector.Discover(context.Background(), Target{})
	if err != nil {
		t.Fatal(err)
	}
	store, validation := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !validation.Valid {
		t.Fatal(validation.Issues)
	}
	evaluator, err := attestation.New("test")
	if err != nil {
		t.Fatal(err)
	}
	controls := store.LatestByVendor("aws")
	if len(controls) != 10 {
		t.Fatalf("controls=%d, want 10", len(controls))
	}
	for _, c := range controls {
		result, err := evaluator.Evaluate(c, got, got.ObservedAt)
		if err != nil {
			t.Fatalf("%s: %v", c.Metadata.ID, err)
		}
		if result.Result != "pass" {
			t.Errorf("%s=%s, want pass", c.Metadata.ID, result.Result)
		}
	}
}

func TestOptionalControlsAreNotApplicable(t *testing.T) {
	snapshot := loadSnapshot(t)
	snapshot.DelegatedAdministratorsRequired = false
	snapshot.RequiredSecurityHubStandardsConfigured = false
	snapshot.SecurityLakeRequired = false
	store, validation := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !validation.Valid {
		t.Fatal(validation.Issues)
	}
	evaluator, _ := attestation.New("test")
	for _, id := range []string{"aws.guardduty.delegated_admin", "aws.securityhub.delegated_admin", "aws.securityhub.required_standards", "aws.securitylake.regions_enabled"} {
		c, err := store.Get(id, "")
		if err != nil {
			t.Fatal(err)
		}
		result, err := evaluator.Evaluate(c, snapshot, snapshot.ObservedAt)
		if err != nil || result.Result != "not_applicable" {
			t.Fatalf("%s result=%s err=%v", id, result.Result, err)
		}
	}
}

func TestCollectionErrorIsReturnedWithoutPartialEvidence(t *testing.T) {
	_, err := NewCollector(fixtureAPI{err: errors.New("AccessDenied")}).Discover(context.Background(), Target{})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloudFormationPlanIsReviewableAndCredentialFree(t *testing.T) {
	plan, err := GenerateCloudFormationPlan("trisoc-organization-trail")
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal(plan.Template, &template); err != nil {
		t.Fatal(err)
	}
	raw := string(plan.Template)
	for _, required := range []string{"AWS::CloudTrail::Trail", "IsOrganizationTrail", "EnableLogFileValidation", "PublicAccessBlockConfiguration", "KMSKeyArn"} {
		if !strings.Contains(raw, required) {
			t.Errorf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"AccessKey", "SecretAccessKey", "SessionToken"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("template contains credential field %q", forbidden)
		}
	}
}

func TestReadOnlyPolicyContainsNoMutationActions(t *testing.T) {
	raw, err := ReadOnlyPolicyJSON()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Statement []struct {
			Action []string `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, statement := range document.Statement {
		for _, action := range statement.Action {
			_, name, _ := strings.Cut(action, ":")
			if !(strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "Describe")) {
				t.Fatalf("policy contains non-read action %q", action)
			}
		}
	}
}

func TestRecordedCloudTrailResponseNormalisation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "aws", "cloudtrail_describe_trails.json"))
	if err != nil {
		t.Fatal(err)
	}
	var response cloudtrail.DescribeTrailsOutput
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.TrailList) != 1 {
		t.Fatalf("trails=%d", len(response.TrailList))
	}
	trail := normaliseTrail(response.TrailList[0])
	if !trail.OrganizationTrail || !trail.MultiRegion || !trail.LogFileValidation || !trail.KMSEncrypted {
		t.Fatalf("unexpected normalized trail: %+v", trail)
	}
}

func TestTargetValidationAndSecretRedaction(t *testing.T) {
	valid := Target{HomeRegion: "ap-southeast-2", GovernedRegions: []string{"ap-southeast-2"}, Architecture: SecurityHubFindingsCentric, ExternalID: "must-not-serialize"}
	if err := validateTarget(valid); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(valid)
	if strings.Contains(string(raw), "must-not-serialize") || strings.Contains(string(raw), "externalId") {
		t.Fatalf("external ID serialized: %s", raw)
	}
	valid.GovernedRegions = []string{"ap-southeast-2", "ap-southeast-2"}
	if err := validateTarget(valid); err == nil {
		t.Fatal("duplicate region accepted")
	}
}

func loadSnapshot(t *testing.T) Snapshot {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "aws", "security_operations_snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
