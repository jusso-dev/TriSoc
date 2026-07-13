package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHashIsDeterministicAndRedactsSecrets(t *testing.T) {
	now := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	record := Record{
		Provider: "aws", Operation: "cloudtrail.describeTrails", Scope: "o-example", ResourceIDs: []string{"trail/example"},
		ObservedAt: now, CollectorIdentity: "arn:aws:iam::123456789012:role/attestor", EvaluatorVersion: "0.1.0", ControlVersion: "1.0.0", Result: "pass", Explanation: "Evidence was collected with Authorization=secret", ValidUntil: now.Add(time.Hour),
		Configuration: map[string]any{"enabled": true, "accessToken": "do-not-store", "nested": map[string]any{"password": "also-secret"}, "header": "Bearer eyJ.secret.value"},
	}
	hashA, canonicalA, err := Hash(record)
	if err != nil {
		t.Fatal(err)
	}
	hashB, canonicalB, err := Hash(record)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB || string(canonicalA) != string(canonicalB) {
		t.Fatal("hashing is not deterministic")
	}
	if !strings.HasPrefix(hashA, "sha256:") || len(hashA) != 71 {
		t.Fatalf("unexpected hash %q", hashA)
	}
	if strings.Contains(string(canonicalA), "do-not-store") || strings.Contains(string(canonicalA), "also-secret") || strings.Contains(string(canonicalA), "eyJ.secret.value") {
		t.Fatalf("secret leaked: %s", canonicalA)
	}
	var decoded map[string]any
	if err := json.Unmarshal(canonicalA, &decoded); err != nil {
		t.Fatal(err)
	}
	configuration := decoded["configuration"].(map[string]any)
	if configuration["accessToken"] != "[REDACTED]" {
		t.Fatalf("token not redacted: %+v", configuration)
	}
}

func TestHashChangesWithMaterialEvidence(t *testing.T) {
	record := Record{Provider: "google", Operation: "logging.organizations.sinks.list", Scope: "organizations/1", ObservedAt: time.Now().UTC(), Configuration: map[string]any{"enabled": true}}
	hashA, _, _ := Hash(record)
	record.Configuration["enabled"] = false
	hashB, _, _ := Hash(record)
	if hashA == hashB {
		t.Fatal("material evidence change did not change hash")
	}
}
