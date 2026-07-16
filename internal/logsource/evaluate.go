package logsource

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var expectedStandards = map[string]string{
	MicrosoftSentinel:        "ASIM",
	AWSSecurityLake:          "OCSF",
	GoogleSecurityOperations: "UDM",
	Splunk:                   "CIM",
}

func Evaluate(inventory Inventory, evaluatedAt time.Time) (Report, error) {
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	} else {
		evaluatedAt = evaluatedAt.UTC()
	}
	policy := withPolicyDefaults(inventory.Policy)
	if err := validateInventory(inventory, policy); err != nil {
		return Report{}, err
	}

	report := Report{
		Compliant:         true,
		EvaluatedAt:       evaluatedAt,
		Policy:            policy,
		ExpectedStandards: ExpectedStandards(),
		Sources:           make([]SourceResult, 0, len(inventory.Sources)),
		Requirements:      make([]Check, 0, len(policy.Requirements)),
	}
	for _, source := range inventory.Sources {
		platform, _ := CanonicalPlatform(source.Platform)
		source.Platform = platform
		result := evaluateSource(source, policy, evaluatedAt)
		report.Sources = append(report.Sources, result)
		report.Summary.Sources++
		if result.Compliant {
			report.Summary.CompliantSources++
		} else {
			report.Compliant = false
		}
		for _, check := range result.Checks {
			countStatus(&report.Summary, check.Status)
		}
	}
	for _, requirement := range policy.Requirements {
		check := evaluateRequirement(requirement, inventory.Sources)
		report.Requirements = append(report.Requirements, check)
		if check.Status != Pass {
			report.Compliant = false
		}
		countStatus(&report.Summary, check.Status)
	}
	return report, nil
}

func ExpectedStandards() map[string]string {
	out := make(map[string]string, len(expectedStandards))
	for platform, standard := range expectedStandards {
		out[platform] = standard
	}
	return out
}

func CanonicalPlatform(value string) (string, bool) {
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(value)))
	switch normalized {
	case "microsoft_sentinel", "azure_sentinel", "sentinel", "microsoft":
		return MicrosoftSentinel, true
	case "aws_security_lake", "security_lake", "aws", "amazon_security_lake":
		return AWSSecurityLake, true
	case "google_security_operations", "google_secops", "chronicle", "gcp_secops", "google":
		return GoogleSecurityOperations, true
	case "splunk", "splunk_enterprise_security", "splunk_es":
		return Splunk, true
	default:
		return "", false
	}
}

func withPolicyDefaults(policy Policy) Policy {
	if policy.MinimumRetentionDays == 0 {
		policy.MinimumRetentionDays = 90
	}
	if policy.MaximumEventAgeMinutes == 0 {
		policy.MaximumEventAgeMinutes = 60
	}
	if policy.MinimumNormalizationCoverage == 0 {
		policy.MinimumNormalizationCoverage = 95
	}
	for i := range policy.Requirements {
		if policy.Requirements[i].MinimumCount == 0 {
			policy.Requirements[i].MinimumCount = 1
		}
		if platform, ok := CanonicalPlatform(policy.Requirements[i].Platform); ok {
			policy.Requirements[i].Platform = platform
		}
	}
	return policy
}

func validateInventory(inventory Inventory, policy Policy) error {
	if inventory.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if inventory.Kind != Kind {
		return fmt.Errorf("kind must be %q", Kind)
	}
	if len(inventory.Sources) == 0 {
		return fmt.Errorf("at least one log source is required")
	}
	if len(inventory.Sources) > 10000 {
		return fmt.Errorf("at most 10000 log sources are permitted")
	}
	if len(policy.Requirements) > 1000 {
		return fmt.Errorf("at most 1000 log-source requirements are permitted")
	}
	if policy.MinimumRetentionDays < 1 || policy.MinimumRetentionDays > 3650 {
		return fmt.Errorf("minimumRetentionDays must be between 1 and 3650")
	}
	if policy.MaximumEventAgeMinutes < 1 || policy.MaximumEventAgeMinutes > 525600 {
		return fmt.Errorf("maximumEventAgeMinutes must be between 1 and 525600")
	}
	if policy.MinimumNormalizationCoverage <= 0 || policy.MinimumNormalizationCoverage > 100 {
		return fmt.Errorf("minimumNormalizationCoverage must be greater than 0 and at most 100")
	}
	seen := make(map[string]bool, len(inventory.Sources))
	for i, source := range inventory.Sources {
		path := fmt.Sprintf("sources[%d]", i)
		trimmedID := strings.TrimSpace(source.ID)
		if trimmedID == "" {
			return fmt.Errorf("%s.id is required", path)
		}
		if trimmedID != source.ID || len(source.ID) > 256 {
			return fmt.Errorf("%s.id must be at most 256 characters with no surrounding whitespace", path)
		}
		identity := strings.ToLower(source.ID)
		if seen[identity] {
			return fmt.Errorf("duplicate log source id %q", source.ID)
		}
		seen[identity] = true
		if _, ok := CanonicalPlatform(source.Platform); !ok {
			return fmt.Errorf("%s.platform %q is unsupported", path, source.Platform)
		}
		if strings.TrimSpace(source.Name) == "" || strings.TrimSpace(source.Category) == "" {
			return fmt.Errorf("%s.name and category are required", path)
		}
		if len(source.Name) > 256 || len(source.Category) > 128 {
			return fmt.Errorf("%s.name must be at most 256 characters and category at most 128", path)
		}
		if source.RetentionDays < 0 || source.RetentionDays > 3650 {
			return fmt.Errorf("%s.retentionDays must be between 0 and 3650", path)
		}
		if len(source.Normalization.Standard) > 32 || len(source.Normalization.Schema) > 256 || len(source.Normalization.Version) > 64 {
			return fmt.Errorf("%s.normalization fields exceed their size limits", path)
		}
		if source.Normalization.CoveragePercent < 0 || source.Normalization.CoveragePercent > 100 {
			return fmt.Errorf("%s.normalization.coveragePercent must be between 0 and 100", path)
		}
	}
	for i, requirement := range policy.Requirements {
		if _, ok := CanonicalPlatform(requirement.Platform); !ok {
			return fmt.Errorf("policy.requirements[%d].platform %q is unsupported", i, requirement.Platform)
		}
		if strings.TrimSpace(requirement.SourceID) == "" && strings.TrimSpace(requirement.Category) == "" {
			return fmt.Errorf("policy.requirements[%d] must set sourceId or category", i)
		}
		if len(requirement.SourceID) > 256 || len(requirement.Category) > 128 {
			return fmt.Errorf("policy.requirements[%d] sourceId or category exceeds its size limit", i)
		}
		if requirement.MinimumCount < 1 || requirement.MinimumCount > 10000 {
			return fmt.Errorf("policy.requirements[%d].minimumCount must be between 1 and 10000", i)
		}
	}
	return nil
}

func evaluateSource(source Source, policy Policy, evaluatedAt time.Time) SourceResult {
	expected := expectedStandards[source.Platform]
	checks := []Check{
		newCheck(source, "enabled", source.Enabled, Fail, "source is enabled", "source is disabled"),
		newCheck(source, "retention", source.RetentionDays >= policy.MinimumRetentionDays, Fail,
			fmt.Sprintf("retention is %d days", source.RetentionDays),
			fmt.Sprintf("retention is %d days; policy requires at least %d", source.RetentionDays, policy.MinimumRetentionDays)),
		newCheck(source, "normalization_standard", strings.EqualFold(strings.TrimSpace(source.Normalization.Standard), expected), Fail,
			fmt.Sprintf("normalization standard is %s", expected),
			fmt.Sprintf("normalization standard is %q; %s requires %s", source.Normalization.Standard, source.Platform, expected)),
		newCheck(source, "normalization_schema", strings.TrimSpace(source.Normalization.Schema) != "", Fail,
			"normalization schema or data model is declared", "normalization schema or data model is missing"),
		newCheck(source, "normalization_coverage", source.Normalization.CoveragePercent >= policy.MinimumNormalizationCoverage, Fail,
			fmt.Sprintf("normalization coverage is %.2f%%", source.Normalization.CoveragePercent),
			fmt.Sprintf("normalization coverage is %.2f%%; policy requires at least %.2f%%", source.Normalization.CoveragePercent, policy.MinimumNormalizationCoverage)),
		newCheck(source, "normalization_validation", source.Normalization.Validated, Fail,
			"normalization mapping has been validated", "normalization mapping has not been validated"),
	}
	checks = append(checks, freshnessCheck(source, policy, evaluatedAt))
	compliant := true
	for _, check := range checks {
		if check.Status != Pass {
			compliant = false
		}
	}
	return SourceResult{ID: source.ID, Platform: source.Platform, Compliant: compliant, Checks: checks}
}

func freshnessCheck(source Source, policy Policy, evaluatedAt time.Time) Check {
	check := Check{Name: "freshness", SourceID: source.ID, Platform: source.Platform}
	if source.LastEventAt == nil {
		check.Status = Unknown
		check.Message = "last event time is unavailable; freshness cannot be proven"
		return check
	}
	lastEvent := source.LastEventAt.UTC()
	if lastEvent.After(evaluatedAt) {
		check.Status = Unknown
		check.Message = "last event time is in the future; collector clock or evidence is invalid"
		return check
	}
	age := evaluatedAt.Sub(lastEvent)
	maximumAge := time.Duration(policy.MaximumEventAgeMinutes) * time.Minute
	if age > maximumAge {
		check.Status = Fail
		check.Message = fmt.Sprintf("last event is %s old; policy allows %s", age.Round(time.Minute), maximumAge)
		return check
	}
	check.Status = Pass
	check.Message = fmt.Sprintf("last event is %s old", age.Round(time.Second))
	return check
}

func evaluateRequirement(requirement Requirement, sources []Source) Check {
	platform, _ := CanonicalPlatform(requirement.Platform)
	count := 0
	for _, source := range sources {
		sourcePlatform, _ := CanonicalPlatform(source.Platform)
		if sourcePlatform != platform {
			continue
		}
		if requirement.SourceID != "" && !strings.EqualFold(source.ID, requirement.SourceID) {
			continue
		}
		if requirement.Category != "" && !strings.EqualFold(source.Category, requirement.Category) {
			continue
		}
		count++
	}
	description := requirement.SourceID
	if description == "" {
		description = "category " + requirement.Category
	}
	status := Pass
	if count < requirement.MinimumCount {
		status = Fail
	}
	return Check{
		Name:     "required_source",
		Status:   status,
		Platform: platform,
		Message:  fmt.Sprintf("found %d of %d required %s source(s)", count, requirement.MinimumCount, description),
	}
}

func newCheck(source Source, name string, passed bool, failure Status, successMessage, failureMessage string) Check {
	status, message := failure, failureMessage
	if passed {
		status, message = Pass, successMessage
	}
	return Check{Name: name, Status: status, Message: message, SourceID: source.ID, Platform: source.Platform}
}

func countStatus(summary *Summary, status Status) {
	switch status {
	case Fail:
		summary.FailedChecks++
	case Unknown:
		summary.UnknownChecks++
	}
}

func SupportedPlatforms() []string {
	platforms := make([]string, 0, len(expectedStandards))
	for platform := range expectedStandards {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	return platforms
}
