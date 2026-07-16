package logsource

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateCompliantInventoryIncludesSplunkCIM(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	platforms := []struct {
		platform string
		standard string
	}{
		{"sentinel", "asim"},
		{"aws", "OCSF"},
		{"chronicle", "UDM"},
		{"splunk_es", "CIM"},
	}
	sources := make([]Source, 0, len(platforms))
	for _, item := range platforms {
		lastEvent := now.Add(-5 * time.Minute)
		sources = append(sources, Source{
			ID: item.platform, Platform: item.platform, Name: item.platform, Category: "authentication", Enabled: true,
			LastEventAt: &lastEvent, RetentionDays: 365,
			Normalization: Normalization{Standard: item.standard, Schema: "Authentication", Version: "1", CoveragePercent: 99, Validated: true},
		})
	}
	inventory := Inventory{APIVersion: APIVersion, Kind: Kind, Policy: Policy{Requirements: []Requirement{{Platform: "splunk", Category: "authentication"}}}, Sources: sources}
	report, err := Evaluate(inventory, now)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Compliant || report.Summary.CompliantSources != 4 {
		t.Fatalf("report should be compliant: %+v", report)
	}
	if report.ExpectedStandards[Splunk] != "CIM" {
		t.Fatalf("Splunk profile missing: %+v", report.ExpectedStandards)
	}
}

func TestEvaluateFailsStaleUnnormalisedAndMissingSource(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	lastEvent := now.Add(-2 * time.Hour)
	inventory := Inventory{
		APIVersion: APIVersion,
		Kind:       Kind,
		Policy: Policy{
			MinimumRetentionDays: 30, MaximumEventAgeMinutes: 60, MinimumNormalizationCoverage: 95,
			Requirements: []Requirement{{Platform: Splunk, SourceID: "missing"}},
		},
		Sources: []Source{{
			ID: "audit", Platform: Splunk, Name: "Audit", Category: "audit", Enabled: true, LastEventAt: &lastEvent, RetentionDays: 7,
			Normalization: Normalization{Standard: "UDM", CoveragePercent: 50},
		}},
	}
	report, err := Evaluate(inventory, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Compliant || report.Summary.FailedChecks < 5 {
		t.Fatalf("expected multiple compliance failures: %+v", report)
	}
	if report.Requirements[0].Status != Fail {
		t.Fatalf("missing required source passed: %+v", report.Requirements)
	}
}

func TestEvaluateTreatsMissingOrFutureFreshnessAsUnknown(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Minute)
	base := Source{ID: "one", Platform: MicrosoftSentinel, Name: "One", Category: "audit", Enabled: true, RetentionDays: 90, Normalization: Normalization{Standard: "ASIM", Schema: "AuditEvent", CoveragePercent: 100, Validated: true}}
	for name, lastEvent := range map[string]*time.Time{"missing": nil, "future": &future} {
		t.Run(name, func(t *testing.T) {
			base.LastEventAt = lastEvent
			report, err := Evaluate(Inventory{APIVersion: APIVersion, Kind: Kind, Sources: []Source{base}}, now)
			if err != nil {
				t.Fatal(err)
			}
			if report.Sources[0].Checks[len(report.Sources[0].Checks)-1].Status != Unknown || report.Compliant {
				t.Fatalf("freshness should be unknown and non-compliant: %+v", report)
			}
		})
	}
}

func TestLoadFileIsStrict(t *testing.T) {
	_, err := LoadFile("testdata/unknown-field.yaml")
	if err == nil || !strings.Contains(err.Error(), "field unexpected") {
		t.Fatalf("unknown field accepted: %v", err)
	}
	_, err = LoadFile("testdata/alias.yaml")
	if err == nil || !strings.Contains(err.Error(), "anchors and aliases") {
		t.Fatalf("YAML alias accepted: %v", err)
	}
}

func TestCanonicalPlatformAliases(t *testing.T) {
	for input, expected := range map[string]string{"Azure Sentinel": MicrosoftSentinel, "security-lake": AWSSecurityLake, "Chronicle": GoogleSecurityOperations, "Splunk ES": Splunk} {
		actual, ok := CanonicalPlatform(input)
		if !ok || actual != expected {
			t.Errorf("CanonicalPlatform(%q)=(%q,%v), want %q", input, actual, ok, expected)
		}
	}
	if _, ok := CanonicalPlatform("unknown"); ok {
		t.Fatal("unknown platform accepted")
	}
}

func TestEvaluateRejectsCaseInsensitiveDuplicateIDs(t *testing.T) {
	base := Source{ID: "Audit", Platform: Splunk, Name: "Audit", Category: "audit"}
	duplicate := base
	duplicate.ID = "audit"
	_, err := Evaluate(Inventory{APIVersion: APIVersion, Kind: Kind, Sources: []Source{base, duplicate}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "duplicate log source id") {
		t.Fatalf("case-insensitive duplicate IDs accepted: %v", err)
	}
}
