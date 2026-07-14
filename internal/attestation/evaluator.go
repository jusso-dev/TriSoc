// Package attestation evaluates exact control versions against redacted,
// provider-specific evidence. Collection errors are represented separately and
// never converted into control failures.
package attestation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/trisoc/attestor/internal/control"
)

type Result struct {
	ControlID        string    `json:"controlId" yaml:"controlId"`
	ControlVersion   string    `json:"controlVersion" yaml:"controlVersion"`
	Result           string    `json:"result" yaml:"result"`
	Technical        string    `json:"technical" yaml:"technical"`
	PlainEnglish     string    `json:"plainEnglish" yaml:"plainEnglish"`
	ObservedAt       time.Time `json:"observedAt" yaml:"observedAt"`
	EvaluatorVersion string    `json:"evaluatorVersion" yaml:"evaluatorVersion"`
}

type Evaluator struct {
	env     *cel.Env
	version string
}

func New(version string) (*Evaluator, error) {
	env, err := cel.NewEnv(cel.Variable("evidence", cel.DynType))
	if err != nil {
		return nil, err
	}
	return &Evaluator{env: env, version: version}, nil
}

func (e *Evaluator) Evaluate(c control.Control, evidence any, observedAt time.Time) (Result, error) {
	base := Result{ControlID: c.Metadata.ID, ControlVersion: c.Metadata.Version, Technical: c.Spec.Explanation.Technical, PlainEnglish: c.Spec.Explanation.PlainEnglish, ObservedAt: observedAt.UTC(), EvaluatorVersion: e.version}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return base, fmt.Errorf("normalise evidence: %w", err)
	}
	var normal any
	if err := json.Unmarshal(raw, &normal); err != nil {
		return base, fmt.Errorf("normalise evidence: %w", err)
	}
	if !applicable(c.Spec.Applicability, normal) {
		base.Result = "not_applicable"
		return base, nil
	}
	ast, issues := e.env.Compile(c.Spec.Evaluator.Expression)
	if issues != nil && issues.Err() != nil {
		return base, fmt.Errorf("compile control %s: %w", c.Metadata.ID, issues.Err())
	}
	program, err := e.env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(100))
	if err != nil {
		return base, fmt.Errorf("create control program: %w", err)
	}
	value, _, err := program.Eval(map[string]any{"evidence": normal})
	if err != nil {
		return base, fmt.Errorf("evaluate control %s: %w", c.Metadata.ID, err)
	}
	if value == types.True {
		base.Result = "pass"
		return base, nil
	}
	if value == types.False {
		base.Result = "fail"
		return base, nil
	}
	return base, fmt.Errorf("control %s returned non-boolean value", c.Metadata.ID)
}

func applicable(rule *control.Applicability, evidence any) bool {
	if rule == nil {
		return true
	}
	for _, condition := range rule.All {
		if !matches(condition, evidence) {
			return false
		}
	}
	if len(rule.Any) > 0 {
		for _, condition := range rule.Any {
			if matches(condition, evidence) {
				return true
			}
		}
		return false
	}
	return true
}
func matches(condition control.Condition, evidence any) bool {
	value, exists := lookup(evidence, condition.Field)
	switch condition.Operator {
	case "exists":
		return exists
	case "equals":
		return equivalent(value, condition.Value)
	case "notEquals":
		return !equivalent(value, condition.Value)
	case "greaterThan":
		a, aok := number(value)
		b, bok := number(condition.Value)
		return aok && bok && a > b
	case "lessThan":
		a, aok := number(value)
		b, bok := number(condition.Value)
		return aok && bok && a < b
	case "contains":
		switch item := value.(type) {
		case string:
			return strings.Contains(item, fmt.Sprint(condition.Value))
		case []any:
			for _, entry := range item {
				if equivalent(entry, condition.Value) {
					return true
				}
			}
		}
	case "in":
		if items, ok := condition.Value.([]any); ok {
			for _, item := range items {
				if equivalent(value, item) {
					return true
				}
			}
		}
	}
	return false
}
func lookup(value any, path string) (any, bool) {
	current := value
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
func equivalent(a, b any) bool {
	if av, aok := number(a); aok {
		if bv, bok := number(b); bok {
			return av == bv
		}
	}
	return reflect.DeepEqual(a, b)
}
func number(value any) (float64, bool) {
	switch n := value.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

func Unknown(c control.Control, observedAt time.Time, collectionErr error) Result {
	return Result{ControlID: c.Metadata.ID, ControlVersion: c.Metadata.Version, Result: "unknown", Technical: fmt.Sprintf("The control could not be assessed because evidence collection failed: %s", collectionErr), PlainEnglish: "TriSOC Attestor could not obtain enough information to assess this control. It has not been marked as passed or failed.", ObservedAt: observedAt.UTC(), EvaluatorVersion: "not-run"}
}
