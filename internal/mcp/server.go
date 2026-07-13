// Package mcp implements the local Model Context Protocol server.
package mcp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trisoc/attestor/internal/control"
)

const (
	serverName      = "trisoc-attestor"
	serverVersion   = "0.1.0-dev"
	protocolVersion = "2025-11-25"
	maxRequestBytes = 1 << 20
	maxListControls = 200
)

type Server struct {
	controls *control.Store
	logger   *slog.Logger
}

func New(store *control.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return &Server{controls: store, logger: logger}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
type toolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) ServeStdio(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxRequestBytes)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		resp, notification := s.handle(line)
		if notification {
			continue
		}
		if err := encoder.Encode(resp); err != nil {
			return fmt.Errorf("write MCP response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP request: %w", err)
	}
	return nil
}

func (s *Server) ServeHTTP(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	authToken := os.Getenv("TRISOC_MCP_AUTH_TOKEN")
	containerMode := os.Getenv("TRISOC_MCP_CONTAINER_MODE") == "true"
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) && !containerMode && len(authToken) < 32 {
		return errors.New("non-loopback MCP HTTP requires a bearer token of at least 32 characters; isolated containers may set TRISOC_MCP_CONTAINER_MODE=true when publishing only to host loopback")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !trustedOrigin(r.Header.Get("Origin")) {
			http.Error(w, `{"error":"untrusted origin"}`, http.StatusForbidden)
			return
		}
		if authToken != "" && !validBearer(r.Header.Get("Authorization"), authToken) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		if version := r.Header.Get("MCP-Protocol-Version"); version != "" && version != protocolVersion {
			http.Error(w, `{"error":"unsupported MCP protocol version"}`, http.StatusBadRequest)
			return
		}
		body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		if readErr != nil {
			http.Error(w, `{"error":"request too large or unreadable"}`, http.StatusBadRequest)
			return
		}
		resp, notification := s.handle(body)
		if notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("encode HTTP MCP response", "error", err)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	httpServer := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func trustedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return (u.Scheme == "http" || u.Scheme == "https") && (host == "localhost" || (ip != nil && ip.IsLoopback()))
}

func validBearer(header, expected string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *Server) handle(data []byte) (response, bool) {
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return fail(nil, -32700, "parse error", nil), false
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return fail(req.ID, -32600, "invalid JSON-RPC request", nil), false
	}
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	if isNotification {
		if req.Method != "notifications/initialized" && req.Method != "notifications/cancelled" {
			s.logger.Warn("unknown MCP notification", "method", req.Method)
		}
		return response{}, true
	}
	switch req.Method {
	case "initialize":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": serverName, "version": serverVersion}, "instructions": "Read-only control catalogue and deterministic validator. No cloud changes can be made by this server."}}, false
	case "ping":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}, false
	case "tools/list":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": toolDefinitions()}}, false
	case "tools/call":
		var call toolCall
		if err := decodeStrict(req.Params, &call); err != nil {
			return fail(req.ID, -32602, "invalid tool call", err.Error()), false
		}
		result, err := s.callTool(call)
		if err != nil {
			return response{JSONRPC: "2.0", ID: req.ID, Result: toolError(err.Error())}, false
		}
		return response{JSONRPC: "2.0", ID: req.ID, Result: toolResult(result)}, false
	default:
		return fail(req.ID, -32601, "method not found", nil), false
	}
}

func (s *Server) callTool(call toolCall) (any, error) {
	switch call.Name {
	case "list_controls":
		var args struct {
			Vendor string `json:"vendor"`
			Limit  int    `json:"limit"`
		}
		if len(call.Arguments) > 0 {
			if err := decodeStrict(call.Arguments, &args); err != nil {
				return nil, err
			}
		}
		if args.Limit <= 0 {
			args.Limit = 50
		}
		if args.Limit > maxListControls {
			args.Limit = maxListControls
		}
		items := make([]control.Control, 0, args.Limit)
		for _, item := range s.controls.List() {
			if args.Vendor != "" && item.Metadata.Vendor != args.Vendor {
				continue
			}
			items = append(items, item)
			if len(items) == args.Limit {
				break
			}
		}
		return map[string]any{"controls": items, "count": len(items), "limit": args.Limit}, nil
	case "get_control":
		var args struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		}
		if err := decodeStrict(call.Arguments, &args); err != nil {
			return nil, err
		}
		if args.ID == "" {
			return nil, errors.New("id is required")
		}
		return s.controls.Get(args.ID, args.Version)
	case "validate_control_bundle":
		var args struct {
			Paths []string `json:"paths"`
		}
		if err := decodeStrict(call.Arguments, &args); err != nil {
			return nil, err
		}
		if len(args.Paths) == 0 {
			args.Paths = []string{"controls"}
		}
		if len(args.Paths) > 20 {
			return nil, errors.New("at most 20 paths may be validated")
		}
		for _, path := range args.Paths {
			if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
				return nil, errors.New("paths must be relative and cannot contain '..'")
			}
		}
		_, result := control.LoadPaths(args.Paths...)
		return result, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", call.Name)
	}
}

func toolDefinitions() []map[string]any {
	readOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	return []map[string]any{
		{"name": "list_controls", "description": "Read-only: list versioned controls. Requires no cloud scopes. Results are capped at 200.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"vendor": map[string]any{"type": "string", "enum": []string{"microsoft", "aws", "google"}}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200}}, "additionalProperties": false}, "annotations": readOnly},
		{"name": "get_control", "description": "Read-only: retrieve an exact control definition. Requires no cloud scopes.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}, "version": map[string]any{"type": "string"}}, "required": []string{"id"}, "additionalProperties": false}, "annotations": readOnly},
		{"name": "validate_control_bundle", "description": "Read-only: validate local control YAML with strict schema, official-source and CEL checks. Does not execute control content.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"paths": map[string]any{"type": "array", "maxItems": 20, "items": map[string]any{"type": "string"}}}, "additionalProperties": false}, "annotations": readOnly},
	}
}

func toolResult(value any) map[string]any {
	raw, _ := json.Marshal(value)
	return map[string]any{"content": []map[string]string{{"type": "text", "text": string(raw)}}, "structuredContent": value, "isError": false}
}
func toolError(message string) map[string]any {
	return map[string]any{"content": []map[string]string{{"type": "text", "text": message}}, "structuredContent": map[string]any{"code": "TOOL_ERROR", "message": message}, "isError": true}
}
func fail(id json.RawMessage, code int, message string, data any) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}}
}
func decodeStrict(data []byte, target any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
