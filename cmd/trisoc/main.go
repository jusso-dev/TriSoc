package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/trisoc/attestor/internal/control"
	"github.com/trisoc/attestor/internal/mcp"
	"gopkg.in/yaml.v3"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "controls":
		return controlsCommand(args[1:])
	case "mcp":
		return mcpCommand(args[1:])
	case "doctor":
		return doctorCommand()
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func controlsCommand(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: trisoc controls validate [paths...] [--output human|json|yaml]")
	}
	format := "human"
	paths := make([]string, 0)
	for i := 1; i < len(args); i++ {
		if args[i] == "--output" {
			if i+1 >= len(args) {
				return errors.New("--output requires a value")
			}
			format = args[i+1]
			i++
			continue
		}
		paths = append(paths, args[i])
	}
	_, result := control.LoadPaths(paths...)
	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "yaml":
		data, _ := yaml.Marshal(result)
		fmt.Print(string(data))
	case "human":
		for _, issue := range result.Issues {
			fmt.Printf("%s: %s: %s\n", strings.ToUpper(issue.Severity), issue.Path, issue.Message)
		}
		if result.Valid {
			fmt.Printf("Validated %d controls in %d files.\n", result.Controls, result.Files)
		} else {
			fmt.Printf("Validation failed: %d issue(s) across %d files.\n", len(result.Issues), result.Files)
		}
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
	if !result.Valid {
		return errors.New("control validation failed")
	}
	return nil
}

func mcpCommand(args []string) error {
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("usage: trisoc mcp serve [--transport stdio|http] [--listen 127.0.0.1:8787]")
	}
	transport := "stdio"
	listen := "127.0.0.1:8787"
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--transport":
			i++
			if i >= len(args) {
				return errors.New("--transport requires a value")
			}
			transport = args[i]
		case "--listen":
			i++
			if i >= len(args) {
				return errors.New("--listen requires a value")
			}
			listen = args[i]
		default:
			return fmt.Errorf("unknown option %q", args[i])
		}
	}
	store, validation := control.LoadDefaultStore()
	if !validation.Valid {
		return fmt.Errorf("control catalogue is invalid: %v", validation.Issues)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := mcp.New(store, logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch transport {
	case "stdio":
		return server.ServeStdio(ctx, os.Stdin, os.Stdout)
	case "http":
		logger.Info("MCP HTTP server starting", "listen", listen)
		return server.ServeHTTP(ctx, listen)
	default:
		return fmt.Errorf("unsupported MCP transport %q", transport)
	}
}

func doctorCommand() error {
	_, result := control.LoadPaths("controls")
	status := "ok"
	if !result.Valid {
		status = "failed"
	}
	fmt.Printf("TriSOC Attestor doctor\ncontrols: %s (%d loaded)\n", status, result.Controls)
	if !result.Valid {
		return errors.New("bundled controls are invalid")
	}
	return nil
}

func usage() {
	fmt.Print(`TriSOC Attestor

Usage:
  trisoc controls validate [paths...] [--output human|json|yaml]
  trisoc mcp serve --transport stdio
  trisoc mcp serve --transport http --listen 127.0.0.1:8787
  trisoc doctor
  trisoc version
`)
}
