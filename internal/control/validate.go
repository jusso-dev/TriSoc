package control

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)+$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	hashPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	durationPattern = regexp.MustCompile(`^[1-9][0-9]*(s|m|h|d)$`)
)

var officialHosts = map[string]bool{
	"learn.microsoft.com":   true,
	"docs.microsoft.com":    true,
	"azure.microsoft.com":   true,
	"docs.aws.amazon.com":   true,
	"aws.amazon.com":        true,
	"cloud.google.com":      true,
	"docs.cloud.google.com": true,
}

type Validator struct{ cel *cel.Env }

func NewValidator() *Validator {
	env, err := cel.NewEnv(cel.Variable("evidence", cel.DynType))
	if err != nil {
		panic(err)
	}
	return &Validator{cel: env}
}

func (v *Validator) Validate(c Control) []ValidationIssue {
	issues := make([]ValidationIssue, 0)
	add := func(path, message string) {
		issues = append(issues, ValidationIssue{Path: path, Severity: "error", Message: message})
	}
	if c.APIVersion != APIVersion {
		add(".apiVersion", "must be "+APIVersion)
	}
	if c.Kind != Kind {
		add(".kind", "must be "+Kind)
	}
	if !idPattern.MatchString(c.Metadata.ID) {
		add(".metadata.id", "must be a namespaced lowercase identifier")
	}
	if strings.TrimSpace(c.Metadata.Title) == "" {
		add(".metadata.title", "is required")
	}
	if !oneOf(c.Metadata.Vendor, "microsoft", "aws", "google") {
		add(".metadata.vendor", "must be microsoft, aws, or google")
	}
	if c.Metadata.Product == "" {
		add(".metadata.product", "is required")
	}
	if c.Metadata.Service == "" {
		add(".metadata.service", "is required")
	}
	if !versionPattern.MatchString(c.Metadata.Version) {
		add(".metadata.version", "must be semantic version syntax")
	}
	if !oneOf(c.Metadata.Status, "draft", "active", "deprecated", "superseded", "disabled_by_organisation_policy") {
		add(".metadata.status", "has an unsupported lifecycle value")
	}
	if c.Metadata.Status == "superseded" && c.Metadata.ReplacedBy == "" {
		add(".metadata.supersedingControlId", "is required for superseded controls")
	}
	if !oneOf(c.Spec.Classification, "vendor_required", "vendor_recommended", "architectural_recommendation", "organisation_policy", "optional_optimisation") {
		add(".spec.classification", "has an unsupported classification")
	}
	if !oneOf(c.Spec.Severity, "critical", "high", "medium", "low", "informational") {
		add(".spec.severity", "has an unsupported severity")
	}
	if len(c.Spec.Scopes) == 0 {
		add(".spec.scopes", "must contain at least one scope")
	}
	if len(c.Spec.RequiredPermissions) == 0 {
		add(".spec.requiredPermissions", "must identify collector permissions")
	}
	if len(c.Spec.Expected) == 0 {
		add(".spec.expected", "must describe the expected state")
	}
	if c.Spec.Collector.Provider != c.Metadata.Vendor {
		add(".spec.collector.provider", "must match metadata.vendor")
	}
	if strings.TrimSpace(c.Spec.Collector.Operation) == "" {
		add(".spec.collector.operation", "is required")
	}
	if c.Spec.Evaluator.Type != "cel" {
		add(".spec.evaluator.type", "only the sandboxed cel evaluator is supported")
	}
	if strings.TrimSpace(c.Spec.Evaluator.Expression) == "" {
		add(".spec.evaluator.expression", "is required")
	} else if ast, celIssues := v.cel.Compile(c.Spec.Evaluator.Expression); celIssues != nil && celIssues.Err() != nil {
		add(".spec.evaluator.expression", celIssues.Err().Error())
	} else if ast.OutputType() != types.BoolType {
		add(".spec.evaluator.expression", "must evaluate to a boolean")
	}
	validateSource(c.Spec.Source, ".spec.source", add)
	for i, ref := range c.Spec.References {
		validateReference(ref, fmt.Sprintf(".spec.references[%d]", i), add)
	}
	if len(strings.Fields(c.Spec.Explanation.Technical)) < 8 {
		add(".spec.explanation.technical", "must provide a meaningful deterministic explanation")
	}
	if len(strings.Fields(c.Spec.Explanation.PlainEnglish)) < 8 {
		add(".spec.explanation.plainEnglish", "must provide a meaningful plain-English explanation")
	}
	if !oneOf(c.Spec.Remediation.Risk, "low", "medium", "high", "destructive") {
		add(".spec.remediation.risk", "has an unsupported risk")
	}
	if !oneOf(c.Spec.Remediation.Automatic, "unsupported", "manual_guidance", "generate_iac", "supported_with_approval") {
		add(".spec.remediation.automatic", "has an unsupported mode")
	}
	if !oneOf(c.Spec.Remediation.CostImpact, "none", "low", "usage_dependent", "potentially_significant", "unknown_review_required") {
		add(".spec.remediation.costImpact", "has an unsupported cost classification")
	}
	if strings.TrimSpace(c.Spec.Remediation.Guidance) == "" {
		add(".spec.remediation.guidance", "is required")
	}
	if c.Spec.Remediation.Destructive && c.Spec.Remediation.Automatic == "supported_with_approval" {
		add(".spec.remediation.automatic", "destructive remediation cannot be automatically applied")
	}
	if len(c.Spec.Evidence.Fields) == 0 {
		add(".spec.evidence.requiredFields", "must list machine-verifiable evidence fields")
	}
	if !durationPattern.MatchString(c.Spec.Freshness) {
		add(".spec.maximumEvidenceAge", "must be a positive duration using s, m, h, or d")
	}
	for group, conditions := range map[string][]Condition{"all": nilSafeAll(c.Spec.Applicability), "any": nilSafeAny(c.Spec.Applicability)} {
		for i, condition := range conditions {
			if condition.Field == "" || !oneOf(condition.Operator, "equals", "notEquals", "greaterThan", "lessThan", "contains", "in", "exists") {
				add(fmt.Sprintf(".spec.applicability.%s[%d]", group, i), "has an invalid field or operator")
			}
		}
	}
	return issues
}

func validateSource(s Source, path string, add func(string, string)) {
	if strings.TrimSpace(s.Title) == "" {
		add(path+".title", "is required")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || !officialHosts[strings.ToLower(u.Hostname())] {
		add(path+".url", "must be an HTTPS URL on an allowlisted official vendor domain")
	}
	if s.RetrievedAt.IsZero() || s.RetrievedAt.After(time.Now().Add(24*time.Hour)) {
		add(path+".retrievedAt", "must be a valid retrieval time that is not in the future")
	}
	if !hashPattern.MatchString(s.ContentHash) {
		add(path+".contentHash", "must be a lowercase sha256 digest")
	}
}

func validateReference(r Reference, path string, add func(string, string)) {
	if r.Title == "" {
		add(path+".title", "is required")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || !officialHosts[strings.ToLower(u.Hostname())] {
		add(path+".url", "must use an allowlisted official vendor domain")
	}
}

func oneOf(value string, values ...string) bool {
	for _, item := range values {
		if value == item {
			return true
		}
	}
	return false
}
func nilSafeAll(a *Applicability) []Condition {
	if a == nil {
		return nil
	}
	return a.All
}
func nilSafeAny(a *Applicability) []Condition {
	if a == nil {
		return nil
	}
	return a.Any
}
