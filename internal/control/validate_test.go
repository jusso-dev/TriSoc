package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledControlsValidate(t *testing.T) {
	_, result := LoadPaths(filepath.Join("..", "..", "controls"))
	if !result.Valid {
		t.Fatalf("bundled controls are invalid: %+v", result.Issues)
	}
	if result.Controls < 3 {
		t.Fatalf("controls = %d, want at least 3", result.Controls)
	}
}

func TestLoadRejectsUnknownFieldsAndAliases(t *testing.T) {
	valid := readBundledControl(t)
	tests := map[string]string{
		"unknown field": strings.Replace(valid, "kind: Control", "kind: Control\nunexpected: true", 1),
		"alias":         strings.Replace(valid, "tags: [health, audit, foundational]", "tags: &tags [health, audit, foundational]\n  copiedTags: *tags", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Fatal("LoadFile succeeded, want error")
			}
		})
	}
}

func TestValidatorRejectsUntrustedSourceAndNonBooleanCEL(t *testing.T) {
	control, err := LoadFile(filepath.Join("..", "..", "controls", "microsoft-sentinel", "sentinel.health_monitoring.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	control.Spec.Source.URL = "https://example.com/guidance"
	control.Spec.Evaluator.Expression = `"pass"`
	issues := NewValidator().Validate(control)
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, issue.Message)
	}
	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "allowlisted official vendor domain") {
		t.Fatalf("missing source issue: %s", joined)
	}
	if !strings.Contains(joined, "must evaluate to a boolean") {
		t.Fatalf("missing CEL type issue: %s", joined)
	}
}

func TestDuplicateControlVersionRejected(t *testing.T) {
	dir := t.TempDir()
	contents := readBundledControl(t)
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, result := LoadPaths(dir)
	if result.Valid || !strings.Contains(result.Issues[len(result.Issues)-1].Message, "duplicate control") {
		t.Fatalf("want duplicate issue, got %+v", result)
	}
}

func readBundledControl(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "controls", "microsoft-sentinel", "sentinel.health_monitoring.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
