package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/trisoc/attestor/internal/attestation"
	"github.com/trisoc/attestor/internal/control"
	"github.com/trisoc/attestor/internal/logsource"
	"github.com/trisoc/attestor/internal/maturity"
	"github.com/trisoc/attestor/internal/mcp"
	awsprovider "github.com/trisoc/attestor/providers/aws"
	azureprovider "github.com/trisoc/attestor/providers/azure"
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
	case "log-sources":
		return logSourcesCommand(args[1:])
	case "maturity":
		return maturityCommand(args[1:])
	case "siem":
		return siemCommand(args[1:])
	case "mcp":
		return mcpCommand(args[1:])
	case "azure":
		return azureCommand(args[1:])
	case "aws":
		return awsCommand(args[1:])
	case "permissions":
		return permissionsCommand(args[1:])
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

func maturityCommand(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: trisoc maturity check ASSESSMENT [--output human|json|yaml]")
	}
	format := "human"
	var path string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--output":
			i++
			if i >= len(args) {
				return errors.New("--output requires a value")
			}
			format = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if path != "" {
				return errors.New("exactly one SOC maturity assessment path is required")
			}
			path = args[i]
		}
	}
	if path == "" {
		return errors.New("a SOC maturity assessment path is required")
	}
	assessment, err := maturity.LoadFile(path)
	if err != nil {
		return err
	}
	report, err := maturity.Evaluate(assessment)
	if err != nil {
		return err
	}
	if err := printValue(report, format); err != nil {
		return err
	}
	if !report.Compliant {
		return errors.New("SOC maturity check failed")
	}
	return nil
}

func siemCommand(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: trisoc siem check --log-sources INVENTORY --maturity ASSESSMENT [--at RFC3339] [--output human|json|yaml]")
	}
	format := "human"
	var inventoryPath, assessmentPath string
	var evaluatedAt time.Time
	for i := 1; i < len(args); i++ {
		next := func() (string, error) {
			i++
			if i >= len(args) {
				return "", fmt.Errorf("%s requires a value", args[i-1])
			}
			return args[i], nil
		}
		switch args[i] {
		case "--log-sources":
			value, err := next()
			if err != nil {
				return err
			}
			inventoryPath = value
		case "--maturity":
			value, err := next()
			if err != nil {
				return err
			}
			assessmentPath = value
		case "--at":
			value, err := next()
			if err != nil {
				return err
			}
			evaluatedAt, err = time.Parse(time.RFC3339, value)
			if err != nil {
				return fmt.Errorf("invalid --at time: %w", err)
			}
		case "--output":
			value, err := next()
			if err != nil {
				return err
			}
			format = value
		default:
			return fmt.Errorf("unknown option %q", args[i])
		}
	}
	if inventoryPath == "" || assessmentPath == "" {
		return errors.New("--log-sources and --maturity are both required")
	}
	inventory, err := logsource.LoadFile(inventoryPath)
	if err != nil {
		return err
	}
	logReport, err := logsource.Evaluate(inventory, evaluatedAt)
	if err != nil {
		return err
	}
	assessment, err := maturity.LoadFile(assessmentPath)
	if err != nil {
		return err
	}
	maturityReport, err := maturity.Evaluate(assessment)
	if err != nil {
		return err
	}
	result := struct {
		Compliant  bool             `json:"compliant" yaml:"compliant"`
		LogSources logsource.Report `json:"logSources" yaml:"logSources"`
		Maturity   maturity.Report  `json:"maturity" yaml:"maturity"`
	}{Compliant: logReport.Compliant && maturityReport.Compliant, LogSources: logReport, Maturity: maturityReport}
	if err := printValue(result, format); err != nil {
		return err
	}
	if !result.Compliant {
		return errors.New("SIEM implementation check failed")
	}
	return nil
}

func logSourcesCommand(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: trisoc log-sources check INVENTORY [--at RFC3339] [--output human|json|yaml]")
	}
	format := "human"
	var evaluatedAt time.Time
	var path string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--output":
			i++
			if i >= len(args) {
				return errors.New("--output requires a value")
			}
			format = args[i]
		case "--at":
			i++
			if i >= len(args) {
				return errors.New("--at requires a value")
			}
			parsed, err := time.Parse(time.RFC3339, args[i])
			if err != nil {
				return fmt.Errorf("invalid --at time: %w", err)
			}
			evaluatedAt = parsed
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if path != "" {
				return errors.New("exactly one log-source inventory path is required")
			}
			path = args[i]
		}
	}
	if path == "" {
		return errors.New("a log-source inventory path is required")
	}
	inventory, err := logsource.LoadFile(path)
	if err != nil {
		return err
	}
	report, err := logsource.Evaluate(inventory, evaluatedAt)
	if err != nil {
		return err
	}
	if err := printValue(report, format); err != nil {
		return err
	}
	if !report.Compliant {
		return errors.New("log-source compliance check failed")
	}
	return nil
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

func azureCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: trisoc azure discover|attest|plan [options]")
	}
	target, format, err := parseAzureTarget(args[1:])
	if err != nil {
		return err
	}
	switch args[0] {
	case "plan":
		plan, err := azureprovider.GenerateBicepPlan(target)
		if err != nil {
			return err
		}
		if format == "bicep" {
			fmt.Print(plan.Source)
			return nil
		}
		return printValue(plan, format)
	case "discover", "attest":
		api, err := azureprovider.NewDefaultAPI(target.SubscriptionID)
		if err != nil {
			return err
		}
		identity := os.Getenv("AZURE_CLIENT_ID")
		if identity == "" {
			identity = "azure-default-credential"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		snapshot, err := azureprovider.NewCollector(api, identity).Discover(ctx, target)
		if args[0] == "discover" {
			if err != nil {
				return err
			}
			return printValue(snapshot, format)
		}
		store, validation := control.LoadDefaultStore()
		if !validation.Valid {
			return fmt.Errorf("control catalogue is invalid: %v", validation.Issues)
		}
		evaluator, err := attestation.New(version)
		if err != nil {
			return err
		}
		results := make([]attestation.Result, 0)
		if err != nil {
			observed := time.Now().UTC()
			for _, c := range store.LatestByVendor("microsoft") {
				results = append(results, attestation.Unknown(c, observed, err))
			}
			return printValue(map[string]any{"provider": "microsoft", "collectionError": err.Error(), "results": results}, format)
		}
		for _, c := range store.LatestByVendor("microsoft") {
			result, evaluateErr := evaluator.Evaluate(c, snapshot, snapshot.ObservedAt)
			if evaluateErr != nil {
				result = attestation.Unknown(c, snapshot.ObservedAt, evaluateErr)
			}
			results = append(results, result)
		}
		return printValue(map[string]any{"provider": "microsoft", "snapshot": snapshot, "results": results}, format)
	default:
		return fmt.Errorf("unknown azure command %q", args[0])
	}
}

func permissionsCommand(args []string) error {
	if len(args) == 0 || args[0] != "explain" {
		return errors.New("usage: trisoc permissions explain --provider azure|aws|gcp [--output json|yaml|human]")
	}
	provider, format := "", "human"
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			return fmt.Errorf("%s requires a value", args[i])
		}
		switch args[i] {
		case "--provider":
			i++
			provider = args[i]
		case "--output":
			i++
			format = args[i]
		default:
			return fmt.Errorf("unknown option %q", args[i])
		}
	}
	vendor := map[string]string{"azure": "microsoft", "aws": "aws", "gcp": "google"}[provider]
	if vendor == "" {
		return fmt.Errorf("unsupported provider %q", provider)
	}
	store, validation := control.LoadDefaultStore()
	if !validation.Valid {
		return fmt.Errorf("control catalogue is invalid: %v", validation.Issues)
	}
	type item struct {
		Permission     string   `json:"permission" yaml:"permission"`
		Controls       []string `json:"controls" yaml:"controls"`
		ReadOnly       bool     `json:"readOnly" yaml:"readOnly"`
		CapabilityLost string   `json:"capabilityLost" yaml:"capabilityLost"`
	}
	byPermission := map[string][]string{}
	for _, c := range store.LatestByVendor(vendor) {
		for _, permission := range c.Spec.RequiredPermissions {
			byPermission[permission] = append(byPermission[permission], c.Metadata.ID)
		}
	}
	permissions := make([]string, 0, len(byPermission))
	for permission := range byPermission {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	out := make([]item, 0, len(permissions))
	for _, permission := range permissions {
		controls := byPermission[permission]
		sort.Strings(controls)
		readOnly := isReadOnlyPermission(permission)
		out = append(out, item{Permission: permission, Controls: controls, ReadOnly: readOnly, CapabilityLost: "Controls listed for this permission become unknown when it is omitted."})
	}
	return printValue(map[string]any{"provider": provider, "permissions": out}, format)
}

func isReadOnlyPermission(permission string) bool {
	lower := strings.ToLower(permission)
	if strings.HasSuffix(lower, "/read") || strings.Contains(lower, "query/read") || strings.HasPrefix(lower, "logging.") && strings.HasSuffix(lower, ".get") {
		return true
	}
	if _, action, ok := strings.Cut(permission, ":"); ok {
		return strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "BatchGet")
	}
	return false
}

func awsCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: trisoc aws discover|attest|plan [options]")
	}
	target, trailName, format, err := parseAWSTarget(args[1:])
	if err != nil {
		return err
	}
	if args[0] == "plan" {
		plan, err := awsprovider.GenerateCloudFormationPlan(trailName)
		if err != nil {
			return err
		}
		if format == "cloudformation" {
			fmt.Println(string(plan.Template))
			return nil
		}
		return printValue(plan, format)
	}
	if args[0] != "discover" && args[0] != "attest" {
		return fmt.Errorf("unknown aws command %q", args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	api, err := awsprovider.NewDefaultAPI(ctx, target)
	if err != nil {
		return err
	}
	snapshot, collectionErr := awsprovider.NewCollector(api).Discover(ctx, target)
	if args[0] == "discover" {
		if collectionErr != nil {
			return collectionErr
		}
		return printValue(snapshot, format)
	}
	store, validation := control.LoadDefaultStore()
	if !validation.Valid {
		return fmt.Errorf("control catalogue is invalid: %v", validation.Issues)
	}
	evaluator, err := attestation.New(version)
	if err != nil {
		return err
	}
	controls := store.LatestByVendor("aws")
	results := make([]attestation.Result, 0, len(controls))
	if collectionErr != nil {
		observed := time.Now().UTC()
		for _, c := range controls {
			results = append(results, attestation.Unknown(c, observed, collectionErr))
		}
		return printValue(map[string]any{"provider": "aws", "collectionError": collectionErr.Error(), "results": results}, format)
	}
	for _, c := range controls {
		result, evaluateErr := evaluator.Evaluate(c, snapshot, snapshot.ObservedAt)
		if evaluateErr != nil {
			result = attestation.Unknown(c, snapshot.ObservedAt, evaluateErr)
		}
		results = append(results, result)
	}
	return printValue(map[string]any{"provider": "aws", "snapshot": snapshot, "results": results}, format)
}

func parseAWSTarget(args []string) (awsprovider.Target, string, string, error) {
	target := awsprovider.Target{HomeRegion: "us-east-1", GovernedRegions: []string{"us-east-1"}, Architecture: awsprovider.SecurityHubFindingsCentric}
	trailName, format := "trisoc-organization-trail", "human"
	for i := 0; i < len(args); i++ {
		next := func() (string, error) {
			i++
			if i >= len(args) {
				return "", fmt.Errorf("%s requires a value", args[i-1])
			}
			return args[i], nil
		}
		var value string
		var err error
		switch args[i] {
		case "--profile", "--role-arn", "--external-id", "--home-region", "--regions", "--architecture", "--securityhub-standards", "--trail-name", "--output":
			value, err = next()
			if err != nil {
				return target, trailName, format, err
			}
			switch args[i-1] {
			case "--profile":
				target.Profile = value
			case "--role-arn":
				target.RoleARN = value
			case "--external-id":
				target.ExternalID = value
			case "--home-region":
				target.HomeRegion = value
			case "--regions":
				target.GovernedRegions = splitCSV(value)
			case "--architecture":
				target.Architecture = awsprovider.Architecture(value)
			case "--securityhub-standards":
				target.RequiredSecurityHubStandards = splitCSV(value)
			case "--trail-name":
				trailName = value
			case "--output":
				format = value
			}
		case "--require-delegated-admins":
			target.RequireDelegatedAdministrators = true
		case "--require-security-lake":
			target.RequireSecurityLake = true
		default:
			return target, trailName, format, fmt.Errorf("unknown option %q", args[i])
		}
	}
	return target, trailName, format, nil
}

func parseAzureTarget(args []string) (azureprovider.Target, string, error) {
	target := azureprovider.Target{MinimumRetentionDays: 90}
	format := "human"
	for i := 0; i < len(args); i++ {
		next := func() (string, error) {
			i++
			if i >= len(args) {
				return "", fmt.Errorf("%s requires a value", args[i-1])
			}
			return args[i], nil
		}
		switch args[i] {
		case "--subscription":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			target.SubscriptionID = v
		case "--resource-group":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			target.ResourceGroup = v
		case "--workspace":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			target.WorkspaceName = v
		case "--minimum-retention":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			n, e := strconv.ParseInt(v, 10, 32)
			if e != nil {
				return target, format, fmt.Errorf("invalid retention: %w", e)
			}
			target.MinimumRetentionDays = int32(n)
		case "--required-connectors":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			target.RequiredConnectors = splitCSV(v)
		case "--expected-tables":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			target.ExpectedTables = splitCSV(v)
		case "--require-automation":
			target.RequireAutomation = true
		case "--output":
			v, e := next()
			if e != nil {
				return target, format, e
			}
			format = v
		default:
			return target, format, fmt.Errorf("unknown option %q", args[i])
		}
	}
	return target, format, nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
func printValue(value any, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "yaml":
		data, err := yaml.Marshal(value)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	case "human":
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func usage() {
	fmt.Print(`TriSOC Attestor

Usage:
  trisoc controls validate [paths...] [--output human|json|yaml]
  trisoc log-sources check INVENTORY [--at RFC3339] [--output human|json|yaml]
  trisoc maturity check ASSESSMENT [--output human|json|yaml]
  trisoc siem check --log-sources INVENTORY --maturity ASSESSMENT [--at RFC3339]
  trisoc mcp serve --transport stdio
  trisoc mcp serve --transport http --listen 127.0.0.1:8787
  trisoc azure discover --subscription ID --resource-group RG --workspace NAME --output json
  trisoc azure attest --subscription ID --resource-group RG --workspace NAME --expected-tables TABLES
  trisoc azure plan --resource-group RG --workspace NAME --minimum-retention 90
  trisoc aws discover --home-region ap-southeast-2 --regions ap-southeast-2,us-east-1
  trisoc aws attest --architecture full_aws_native_soc --require-delegated-admins
  trisoc aws plan --trail-name trisoc-organization-trail --output cloudformation
  trisoc permissions explain --provider azure|aws --output json
  trisoc doctor
  trisoc version
`)
}
