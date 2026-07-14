package attestation

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trisoc/attestor/internal/control"
)

func TestEvaluateBooleanControl(t *testing.T) {
	store, result := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !result.Valid {
		t.Fatal(result.Issues)
	}
	c, err := store.Get("microsoft.sentinel.health_monitoring", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	e, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{"health": map[string]any{"monitoringDataPresent": true}}
	got, err := e.Evaluate(c, evidence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Result != "pass" {
		t.Fatalf("result=%s", got.Result)
	}
}

func TestCollectionErrorIsUnknown(t *testing.T) {
	c := control.Control{Metadata: control.Metadata{ID: "test.control", Version: "1.0.0"}}
	got := Unknown(c, time.Now(), assertionError("denied"))
	if got.Result != "unknown" {
		t.Fatalf("result=%s", got.Result)
	}
}

func TestApplicabilityReturnsNotApplicable(t *testing.T) {
	c := control.Control{Metadata: control.Metadata{ID: "test.control", Version: "1.0.0"}, Spec: control.Spec{Applicability: &control.Applicability{All: []control.Condition{{Field: "featureLicensed", Operator: "equals", Value: true}}}, Evaluator: control.Evaluator{Type: "cel", Expression: "true"}}}
	e, _ := New("test")
	got, err := e.Evaluate(c, map[string]any{"featureLicensed": false}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Result != "not_applicable" {
		t.Fatalf("result=%s", got.Result)
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }
