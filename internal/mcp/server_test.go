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
	if len(tools) != 6 {
		t.Fatalf("tools=%d", len(tools))
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
