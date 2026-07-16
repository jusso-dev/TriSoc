package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trisoc/attestor/internal/control"
)

func TestStdioInitializeAndListTools(t *testing.T) {
	store, result := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !result.Valid {
		t.Fatalf("invalid controls: %+v", result.Issues)
	}
	server := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
	var output bytes.Buffer
	if err := server.ServeStdio(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("responses=%d, want 2: %s", len(lines), output.String())
	}
	var initialized map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &initialized); err != nil {
		t.Fatal(err)
	}
	resultMap := initialized["result"].(map[string]any)
	if resultMap["protocolVersion"] != protocolVersion {
		t.Fatalf("protocol=%v", resultMap["protocolVersion"])
	}
	var listed map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &listed); err != nil {
		t.Fatal(err)
	}
	tools := listed["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("tools=%d", len(tools))
	}
}

func TestSOCMaturityToolFailsClosedOnIncompleteAssessment(t *testing.T) {
	server := New(&control.Store{}, nil)
	value, err := server.callTool(toolCall{Name: "check_soc_maturity", Arguments: json.RawMessage(`{
		"assessment":{
			"apiVersion":"attestor.trisoc.io/v1alpha1",
			"kind":"SOCMaturityAssessment",
			"metadata":{"name":"incomplete"},
			"spec":{"model":"soc-cmm-basic@2.4.2","aspectResults":[],"controlResults":[]}
		}
	}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"compliant":false`) || !strings.Contains(string(raw), `"incompleteAspects":27`) || !strings.Contains(string(raw), `"incompleteControls":45`) {
		t.Fatalf("incomplete assessment did not fail closed: %s", raw)
	}
}

func TestLogSourceToolChecksSplunkCIM(t *testing.T) {
	server := New(&control.Store{}, nil)
	value, err := server.callTool(toolCall{Name: "check_log_sources", Arguments: json.RawMessage(`{
		"evaluatedAt":"2026-07-16T08:00:00Z",
		"inventory":{
			"apiVersion":"attestor.trisoc.io/v1alpha1",
			"kind":"LogSourceInventory",
			"sources":[{
				"id":"splunk-authentication",
				"platform":"splunk",
				"name":"Splunk authentication",
				"category":"authentication",
				"enabled":true,
				"lastEventAt":"2026-07-16T07:55:00Z",
				"retentionDays":90,
				"normalization":{"standard":"CIM","schema":"Authentication","coveragePercent":100,"validated":true}
			}]
		}
	}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"compliant":true`) || !strings.Contains(string(raw), `"splunk":"CIM"`) {
		t.Fatalf("Splunk CIM check missing or failed: %s", raw)
	}
}

func TestGetControlToolAndBoundedPaths(t *testing.T) {
	store, result := control.LoadStore(filepath.Join("..", "..", "controls"))
	if !result.Valid {
		t.Fatal(result.Issues)
	}
	server := New(store, nil)
	value, err := server.callTool(toolCall{Name: "get_control", Arguments: json.RawMessage(`{"id":"aws.cloudtrail.organization_multi_region"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if value.(control.Control).Metadata.Vendor != "aws" {
		t.Fatal("wrong control returned")
	}
	_, err = server.callTool(toolCall{Name: "validate_control_bundle", Arguments: json.RawMessage(`{"paths":["../controls"]}`)})
	if err == nil {
		t.Fatal("parent traversal accepted")
	}
}

func TestWriteToolDoesNotExist(t *testing.T) {
	server := New(&control.Store{}, nil)
	_, err := server.callTool(toolCall{Name: "apply_approved_plan", Arguments: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("write tool unexpectedly available")
	}
}

func TestAWSCloudFormationToolIsPlanningOnly(t *testing.T) {
	server := New(&control.Store{}, nil)
	value, err := server.callTool(toolCall{Name: "generate_aws_cloudformation", Arguments: json.RawMessage(`{"trailName":"trisoc-test-trail"}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "AWS::CloudTrail::Trail") || strings.Contains(string(raw), "SecretAccessKey") {
		t.Fatalf("unsafe or incomplete plan: %s", raw)
	}
	schema, _ := json.Marshal(awsToolSchema())
	if strings.Contains(string(schema), "externalId") || strings.Contains(string(schema), "accessKey") {
		t.Fatalf("credential-like input exposed by MCP: %s", schema)
	}
}

func TestTrustedOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://localhost:3000", "https://127.0.0.1:8787", "http://[::1]:8787"} {
		if !trustedOrigin(origin) {
			t.Errorf("trusted origin rejected: %q", origin)
		}
	}
	for _, origin := range []string{"https://attacker.example", "file:///tmp/test", "://invalid"} {
		if trustedOrigin(origin) {
			t.Errorf("untrusted origin accepted: %q", origin)
		}
	}
}

func TestBearerValidation(t *testing.T) {
	if !validBearer("Bearer correct-token", "correct-token") {
		t.Fatal("correct bearer token rejected")
	}
	for _, header := range []string{"", "Basic correct-token", "Bearer wrong-token"} {
		if validBearer(header, "correct-token") {
			t.Fatalf("invalid bearer token accepted: %q", header)
		}
	}
}
