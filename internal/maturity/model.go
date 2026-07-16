// Package maturity evaluates a completed SOC-CMM Basic profile as a required
// SIEM implementation gate. It records scores and evidence; it does not copy
// or execute spreadsheet formulas.
package maturity

import (
	"embed"
	"encoding/json"
	"fmt"
)

const (
	APIVersion   = "attestor.trisoc.io/v1alpha1"
	Kind         = "SOCMaturityAssessment"
	ModelID      = "soc-cmm-basic"
	ModelVersion = "2.4.2"
	ModelRef     = ModelID + "@" + ModelVersion
)

//go:embed soc-cmm-basic-2.4.2.json
var modelFiles embed.FS

type Model struct {
	ID               string         `json:"id" yaml:"id"`
	Version          string         `json:"version" yaml:"version"`
	Title            string         `json:"title" yaml:"title"`
	Published        string         `json:"published" yaml:"published"`
	Source           string         `json:"source" yaml:"source"`
	Author           string         `json:"author" yaml:"author"`
	License          string         `json:"license" yaml:"license"`
	AdaptationNotice string         `json:"adaptationNotice" yaml:"adaptationNotice"`
	Defaults         ModelDefaults  `json:"defaults" yaml:"defaults"`
	MaturityLevels   []Level        `json:"maturityLevels" yaml:"maturityLevels"`
	CapabilityLevels []Level        `json:"capabilityLevels" yaml:"capabilityLevels"`
	Domains          []Domain       `json:"domains" yaml:"domains"`
	Controls         []ModelControl `json:"siemImplementationControls" yaml:"siemImplementationControls"`
}

type ModelDefaults struct {
	MinimumMaturity   float64 `json:"minimumMaturity" yaml:"minimumMaturity"`
	MinimumCapability float64 `json:"minimumCapability" yaml:"minimumCapability"`
}

type Level struct {
	Value float64 `json:"value" yaml:"value"`
	Name  string  `json:"name" yaml:"name"`
}

type Domain struct {
	ID      string   `json:"id" yaml:"id"`
	Name    string   `json:"name" yaml:"name"`
	Aspects []Aspect `json:"aspects" yaml:"aspects"`
}

type Aspect struct {
	ID                   string `json:"id" yaml:"id"`
	Name                 string `json:"name" yaml:"name"`
	CapabilityApplicable bool   `json:"capabilityApplicable" yaml:"capabilityApplicable"`
}

type ModelControl struct {
	ID          string `json:"id" yaml:"id"`
	AspectID    string `json:"aspectId" yaml:"aspectId"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

type Assessment struct {
	APIVersion string         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string         `json:"kind" yaml:"kind"`
	Metadata   Metadata       `json:"metadata" yaml:"metadata"`
	Spec       AssessmentSpec `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

type AssessmentSpec struct {
	Model          string            `json:"model" yaml:"model"`
	Policy         Policy            `json:"policy" yaml:"policy"`
	AspectResults  []AspectResponse  `json:"aspectResults" yaml:"aspectResults"`
	ControlResults []ControlResponse `json:"controlResults" yaml:"controlResults"`
}

type Policy struct {
	MinimumMaturity   float64 `json:"minimumMaturity" yaml:"minimumMaturity"`
	MinimumCapability float64 `json:"minimumCapability" yaml:"minimumCapability"`
}

type AspectResponse struct {
	ID         string   `json:"id" yaml:"id"`
	Maturity   *float64 `json:"maturity" yaml:"maturity"`
	Capability *float64 `json:"capability,omitempty" yaml:"capability,omitempty"`
	Evidence   []string `json:"evidence" yaml:"evidence"`
}

type ControlResponse struct {
	ID       string   `json:"id" yaml:"id"`
	Status   string   `json:"status" yaml:"status"`
	Evidence []string `json:"evidence" yaml:"evidence"`
}

func BuiltinModel() (Model, error) {
	data, err := modelFiles.ReadFile("soc-cmm-basic-2.4.2.json")
	if err != nil {
		return Model{}, fmt.Errorf("read embedded SOC-CMM model: %w", err)
	}
	var model Model
	if err := json.Unmarshal(data, &model); err != nil {
		return Model{}, fmt.Errorf("decode embedded SOC-CMM model: %w", err)
	}
	if model.ID != ModelID || model.Version != ModelVersion {
		return Model{}, fmt.Errorf("embedded SOC-CMM model identity is invalid")
	}
	return model, nil
}
