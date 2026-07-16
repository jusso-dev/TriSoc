package maturity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinModelShape(t *testing.T) {
	model, err := BuiltinModel()
	if err != nil {
		t.Fatal(err)
	}
	aspects := 0
	for _, domain := range model.Domains {
		aspects += len(domain.Aspects)
	}
	if len(model.Domains) != 5 || aspects != 27 || len(model.Controls) != 45 {
		t.Fatalf("model shape domains=%d aspects=%d controls=%d", len(model.Domains), aspects, len(model.Controls))
	}
	if model.Defaults.MinimumMaturity != 3 || model.Defaults.MinimumCapability != 2 {
		t.Fatalf("unexpected defaults: %+v", model.Defaults)
	}
}

func TestCompleteAssessmentPasses(t *testing.T) {
	report, err := Evaluate(completeAssessment(t))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Compliant || report.Summary.Aspects != 27 || report.Summary.PassingControls != 45 {
		t.Fatalf("unexpected report: %+v", report.Summary)
	}
	if report.OverallMaturity == nil || *report.OverallMaturity != 3 {
		t.Fatalf("overall maturity=%v", report.OverallMaturity)
	}
	if report.OverallCapability == nil || *report.OverallCapability != 2 {
		t.Fatalf("overall capability=%v", report.OverallCapability)
	}
}

func TestMissingScoresEvidenceAndControlsAreIncomplete(t *testing.T) {
	assessment := completeAssessment(t)
	assessment.Spec.AspectResults = assessment.Spec.AspectResults[1:]
	assessment.Spec.ControlResults = assessment.Spec.ControlResults[1:]
	report, err := Evaluate(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if report.Compliant || report.Summary.IncompleteAspects == 0 || report.Summary.IncompleteControls != 1 {
		t.Fatalf("missing results did not fail closed: %+v", report.Summary)
	}
}

func TestBelowTargetAndFailedControlFail(t *testing.T) {
	assessment := completeAssessment(t)
	low := 2.99
	assessment.Spec.AspectResults[0].Maturity = &low
	assessment.Spec.ControlResults[0].Status = StatusFail
	report, err := Evaluate(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if report.Compliant || report.Summary.FailedControls != 1 {
		t.Fatalf("below-target assessment passed: %+v", report.Summary)
	}
}

func TestRejectsWeakenedPolicyUnknownAndDuplicateResults(t *testing.T) {
	for name, mutate := range map[string]func(*Assessment){
		"weakened policy":   func(a *Assessment) { a.Spec.Policy.MinimumMaturity = 2 },
		"unknown aspect":    func(a *Assessment) { a.Spec.AspectResults[0].ID = "X.1" },
		"duplicate control": func(a *Assessment) { a.Spec.ControlResults[1].ID = a.Spec.ControlResults[0].ID },
	} {
		t.Run(name, func(t *testing.T) {
			assessment := completeAssessment(t)
			mutate(&assessment)
			if _, err := Evaluate(assessment); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadFileIsStrictAndRejectsAliases(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(unknown, []byte("apiVersion: attestor.trisoc.io/v1alpha1\nkind: SOCMaturityAssessment\nmetadata: {name: test}\nspec: {model: soc-cmm-basic@2.4.2, unexpected: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(unknown); err == nil || !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("unknown field error=%v", err)
	}
	alias := filepath.Join(dir, "alias.yaml")
	if err := os.WriteFile(alias, []byte("apiVersion: attestor.trisoc.io/v1alpha1\nkind: SOCMaturityAssessment\nmetadata: &m {name: test}\nspec: {model: soc-cmm-basic@2.4.2}\ncopy: *m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(alias); err == nil || !strings.Contains(err.Error(), "anchors and aliases") {
		t.Fatalf("alias error=%v", err)
	}
}

func completeAssessment(t *testing.T) Assessment {
	t.Helper()
	model, err := BuiltinModel()
	if err != nil {
		t.Fatal(err)
	}
	maturity, capability := 3.0, 2.0
	assessment := Assessment{APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: "test-soc"}, Spec: AssessmentSpec{Model: ModelRef}}
	for _, domain := range model.Domains {
		for _, aspect := range domain.Aspects {
			response := AspectResponse{ID: aspect.ID, Maturity: &maturity, Evidence: []string{"evidence/" + aspect.ID}}
			if aspect.CapabilityApplicable {
				response.Capability = &capability
			}
			assessment.Spec.AspectResults = append(assessment.Spec.AspectResults, response)
		}
	}
	for _, control := range model.Controls {
		assessment.Spec.ControlResults = append(assessment.Spec.ControlResults, ControlResponse{ID: control.ID, Status: StatusPass, Evidence: []string{"evidence/" + control.ID}})
	}
	return assessment
}
