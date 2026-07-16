package maturity

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	StatusPass       = "pass"
	StatusFail       = "fail"
	StatusIncomplete = "incomplete"
)

type Check struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	Status  string `json:"status" yaml:"status"`
	Message string `json:"message" yaml:"message"`
}

type AspectResult struct {
	ID                   string   `json:"id" yaml:"id"`
	Domain               string   `json:"domain" yaml:"domain"`
	Name                 string   `json:"name" yaml:"name"`
	Maturity             *float64 `json:"maturity,omitempty" yaml:"maturity,omitempty"`
	Capability           *float64 `json:"capability,omitempty" yaml:"capability,omitempty"`
	CapabilityApplicable bool     `json:"capabilityApplicable" yaml:"capabilityApplicable"`
	EvidenceCount        int      `json:"evidenceCount" yaml:"evidenceCount"`
	Compliant            bool     `json:"compliant" yaml:"compliant"`
	Checks               []Check  `json:"checks" yaml:"checks"`
}

type ControlResult struct {
	ID             string `json:"id" yaml:"id"`
	AspectID       string `json:"aspectId" yaml:"aspectId"`
	Name           string `json:"name" yaml:"name"`
	DeclaredStatus string `json:"declaredStatus,omitempty" yaml:"declaredStatus,omitempty"`
	EvidenceCount  int    `json:"evidenceCount" yaml:"evidenceCount"`
	Status         string `json:"status" yaml:"status"`
	Message        string `json:"message" yaml:"message"`
}

type DomainResult struct {
	ID               string   `json:"id" yaml:"id"`
	Name             string   `json:"name" yaml:"name"`
	Maturity         *float64 `json:"maturity,omitempty" yaml:"maturity,omitempty"`
	Capability       *float64 `json:"capability,omitempty" yaml:"capability,omitempty"`
	Aspects          int      `json:"aspects" yaml:"aspects"`
	CompliantAspects int      `json:"compliantAspects" yaml:"compliantAspects"`
	Compliant        bool     `json:"compliant" yaml:"compliant"`
}

type Summary struct {
	Domains            int `json:"domains" yaml:"domains"`
	Aspects            int `json:"aspects" yaml:"aspects"`
	CompliantAspects   int `json:"compliantAspects" yaml:"compliantAspects"`
	IncompleteAspects  int `json:"incompleteAspects" yaml:"incompleteAspects"`
	Controls           int `json:"controls" yaml:"controls"`
	PassingControls    int `json:"passingControls" yaml:"passingControls"`
	IncompleteControls int `json:"incompleteControls" yaml:"incompleteControls"`
	FailedControls     int `json:"failedControls" yaml:"failedControls"`
}

type Report struct {
	Compliant         bool            `json:"compliant" yaml:"compliant"`
	AssessmentName    string          `json:"assessmentName" yaml:"assessmentName"`
	Model             string          `json:"model" yaml:"model"`
	Source            string          `json:"source" yaml:"source"`
	License           string          `json:"license" yaml:"license"`
	Policy            Policy          `json:"policy" yaml:"policy"`
	OverallMaturity   *float64        `json:"overallMaturity,omitempty" yaml:"overallMaturity,omitempty"`
	OverallCapability *float64        `json:"overallCapability,omitempty" yaml:"overallCapability,omitempty"`
	Domains           []DomainResult  `json:"domains" yaml:"domains"`
	Aspects           []AspectResult  `json:"aspects" yaml:"aspects"`
	Controls          []ControlResult `json:"siemImplementationControls" yaml:"siemImplementationControls"`
	Summary           Summary         `json:"summary" yaml:"summary"`
}

func Evaluate(assessment Assessment) (Report, error) {
	model, err := BuiltinModel()
	if err != nil {
		return Report{}, err
	}
	policy, err := validateAssessment(assessment, model)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Compliant:      true,
		AssessmentName: assessment.Metadata.Name,
		Model:          ModelRef,
		Source:         model.Source,
		License:        model.License,
		Policy:         policy,
		Domains:        make([]DomainResult, 0, len(model.Domains)),
		Aspects:        make([]AspectResult, 0),
		Controls:       make([]ControlResult, 0, len(model.Controls)),
	}

	aspectResponses := make(map[string]AspectResponse, len(assessment.Spec.AspectResults))
	for _, response := range assessment.Spec.AspectResults {
		aspectResponses[response.ID] = response
	}
	var allMaturity, allCapability []float64
	for _, domain := range model.Domains {
		domainResult := DomainResult{ID: domain.ID, Name: domain.Name, Aspects: len(domain.Aspects), Compliant: true}
		var maturityScores, capabilityScores []float64
		for _, aspect := range domain.Aspects {
			result := evaluateAspect(domain, aspect, aspectResponses[aspect.ID], policy)
			report.Aspects = append(report.Aspects, result)
			report.Summary.Aspects++
			if result.Maturity != nil {
				maturityScores = append(maturityScores, *result.Maturity)
				allMaturity = append(allMaturity, *result.Maturity)
			}
			if result.Capability != nil {
				capabilityScores = append(capabilityScores, *result.Capability)
				allCapability = append(allCapability, *result.Capability)
			}
			if result.Compliant {
				domainResult.CompliantAspects++
				report.Summary.CompliantAspects++
			} else {
				domainResult.Compliant = false
				report.Compliant = false
			}
			for _, check := range result.Checks {
				if check.Status == StatusIncomplete {
					report.Summary.IncompleteAspects++
					break
				}
			}
		}
		domainResult.Maturity = average(maturityScores)
		domainResult.Capability = average(capabilityScores)
		report.Domains = append(report.Domains, domainResult)
	}
	report.Summary.Domains = len(report.Domains)
	report.OverallMaturity = average(allMaturity)
	report.OverallCapability = average(allCapability)

	controlResponses := make(map[string]ControlResponse, len(assessment.Spec.ControlResults))
	for _, response := range assessment.Spec.ControlResults {
		controlResponses[response.ID] = response
	}
	for _, control := range model.Controls {
		result := evaluateControl(control, controlResponses[control.ID])
		report.Controls = append(report.Controls, result)
		report.Summary.Controls++
		switch result.Status {
		case StatusPass:
			report.Summary.PassingControls++
		case StatusIncomplete:
			report.Summary.IncompleteControls++
			report.Compliant = false
		case StatusFail:
			report.Summary.FailedControls++
			report.Compliant = false
		}
	}
	return report, nil
}

func validateAssessment(assessment Assessment, model Model) (Policy, error) {
	if assessment.APIVersion != APIVersion {
		return Policy{}, fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if assessment.Kind != Kind {
		return Policy{}, fmt.Errorf("kind must be %q", Kind)
	}
	if strings.TrimSpace(assessment.Metadata.Name) == "" || len(assessment.Metadata.Name) > 256 {
		return Policy{}, fmt.Errorf("metadata.name is required and must be at most 256 characters")
	}
	if assessment.Spec.Model != ModelRef {
		return Policy{}, fmt.Errorf("spec.model must be %q", ModelRef)
	}
	policy := assessment.Spec.Policy
	if policy.MinimumMaturity == 0 {
		policy.MinimumMaturity = model.Defaults.MinimumMaturity
	}
	if policy.MinimumCapability == 0 {
		policy.MinimumCapability = model.Defaults.MinimumCapability
	}
	if policy.MinimumMaturity < model.Defaults.MinimumMaturity || policy.MinimumMaturity > 5 {
		return Policy{}, fmt.Errorf("minimumMaturity must be between %.0f and 5", model.Defaults.MinimumMaturity)
	}
	if policy.MinimumCapability < model.Defaults.MinimumCapability || policy.MinimumCapability > 3 {
		return Policy{}, fmt.Errorf("minimumCapability must be between %.0f and 3", model.Defaults.MinimumCapability)
	}
	if len(assessment.Spec.AspectResults) > 100 || len(assessment.Spec.ControlResults) > 200 {
		return Policy{}, fmt.Errorf("assessment exceeds the result count limit")
	}
	knownAspects := make(map[string]bool)
	for _, domain := range model.Domains {
		for _, aspect := range domain.Aspects {
			knownAspects[aspect.ID] = true
		}
	}
	seen := make(map[string]bool)
	for i, response := range assessment.Spec.AspectResults {
		if !knownAspects[response.ID] {
			return Policy{}, fmt.Errorf("aspectResults[%d].id %q is not in %s", i, response.ID, ModelRef)
		}
		if seen[response.ID] {
			return Policy{}, fmt.Errorf("duplicate aspect result %q", response.ID)
		}
		seen[response.ID] = true
		if response.Maturity != nil && (math.IsNaN(*response.Maturity) || math.IsInf(*response.Maturity, 0) || *response.Maturity < 0 || *response.Maturity > 5) {
			return Policy{}, fmt.Errorf("aspect %s maturity must be between 0 and 5", response.ID)
		}
		if response.Capability != nil && (math.IsNaN(*response.Capability) || math.IsInf(*response.Capability, 0) || *response.Capability < 0 || *response.Capability > 3) {
			return Policy{}, fmt.Errorf("aspect %s capability must be between 0 and 3", response.ID)
		}
		if err := validateEvidence(response.Evidence, "aspect "+response.ID); err != nil {
			return Policy{}, err
		}
	}
	knownControls := make(map[string]bool, len(model.Controls))
	for _, control := range model.Controls {
		knownControls[control.ID] = true
	}
	seen = make(map[string]bool)
	for i, response := range assessment.Spec.ControlResults {
		if !knownControls[response.ID] {
			return Policy{}, fmt.Errorf("controlResults[%d].id %q is not in %s", i, response.ID, ModelRef)
		}
		if seen[response.ID] {
			return Policy{}, fmt.Errorf("duplicate control result %q", response.ID)
		}
		seen[response.ID] = true
		if response.Status != StatusPass && response.Status != StatusFail {
			return Policy{}, fmt.Errorf("control %s status must be pass or fail", response.ID)
		}
		if err := validateEvidence(response.Evidence, "control "+response.ID); err != nil {
			return Policy{}, err
		}
	}
	return policy, nil
}

func validateEvidence(evidence []string, path string) error {
	if len(evidence) > 50 {
		return fmt.Errorf("%s has more than 50 evidence references", path)
	}
	for i, item := range evidence {
		if strings.TrimSpace(item) == "" || len(item) > 2048 {
			return fmt.Errorf("%s evidence[%d] must be non-empty and at most 2048 characters", path, i)
		}
	}
	return nil
}

func evaluateAspect(domain Domain, aspect Aspect, response AspectResponse, policy Policy) AspectResult {
	result := AspectResult{ID: aspect.ID, Domain: domain.Name, Name: aspect.Name, CapabilityApplicable: aspect.CapabilityApplicable, Checks: make([]Check, 0, 3), Compliant: true}
	result.Maturity = response.Maturity
	result.Capability = response.Capability
	result.EvidenceCount = len(response.Evidence)
	result.Checks = append(result.Checks, scoreCheck("maturity", response.Maturity, policy.MinimumMaturity, 5))
	if aspect.CapabilityApplicable {
		result.Checks = append(result.Checks, scoreCheck("capability", response.Capability, policy.MinimumCapability, 3))
	} else if response.Capability != nil {
		result.Checks = append(result.Checks, Check{ID: "capability", Name: "Capability", Status: StatusFail, Message: "capability is not scored for this SOC-CMM domain"})
	}
	evidenceCheck := Check{ID: "evidence", Name: "Evidence", Status: StatusPass, Message: fmt.Sprintf("%d evidence reference(s) supplied", len(response.Evidence))}
	if len(response.Evidence) == 0 {
		evidenceCheck.Status = StatusIncomplete
		evidenceCheck.Message = "at least one evidence reference is required"
	}
	result.Checks = append(result.Checks, evidenceCheck)
	for _, check := range result.Checks {
		if check.Status != StatusPass {
			result.Compliant = false
		}
	}
	return result
}

func scoreCheck(name string, actual *float64, minimum, maximum float64) Check {
	check := Check{ID: name, Name: strings.ToUpper(name[:1]) + name[1:]}
	if actual == nil {
		check.Status = StatusIncomplete
		check.Message = fmt.Sprintf("score is required; target is %.2f", minimum)
		return check
	}
	if *actual < minimum {
		check.Status = StatusFail
		check.Message = fmt.Sprintf("score %.2f is below target %.2f (scale maximum %.0f)", *actual, minimum, maximum)
		return check
	}
	check.Status = StatusPass
	check.Message = fmt.Sprintf("score %.2f meets target %.2f", *actual, minimum)
	return check
}

func evaluateControl(control ModelControl, response ControlResponse) ControlResult {
	result := ControlResult{ID: control.ID, AspectID: control.AspectID, Name: control.Name, DeclaredStatus: response.Status, EvidenceCount: len(response.Evidence)}
	if response.ID == "" {
		result.Status = StatusIncomplete
		result.Message = "required SIEM implementation control has no result"
		return result
	}
	if response.Status != StatusPass {
		result.Status = StatusFail
		result.Message = "control is not implemented"
		return result
	}
	if len(response.Evidence) == 0 {
		result.Status = StatusIncomplete
		result.Message = "passing control requires at least one evidence reference"
		return result
	}
	result.Status = StatusPass
	result.Message = "implemented with evidence"
	return result
}

func average(values []float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	sort.Float64s(values)
	total := 0.0
	for _, value := range values {
		total += value
	}
	result := math.Round((total/float64(len(values)))*100) / 100
	return &result
}
