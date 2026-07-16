// Package logsource evaluates declared SIEM log-source inventories against a
// deterministic operational policy. It does not inspect or persist raw logs.
package logsource

import "time"

const (
	APIVersion = "attestor.trisoc.io/v1alpha1"
	Kind       = "LogSourceInventory"

	MicrosoftSentinel        = "microsoft_sentinel"
	AWSSecurityLake          = "aws_security_lake"
	GoogleSecurityOperations = "google_security_operations"
	Splunk                   = "splunk"
)

type Inventory struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Policy     Policy   `json:"policy" yaml:"policy"`
	Sources    []Source `json:"sources" yaml:"sources"`
}

type Policy struct {
	MinimumRetentionDays         int           `json:"minimumRetentionDays" yaml:"minimumRetentionDays"`
	MaximumEventAgeMinutes       int           `json:"maximumEventAgeMinutes" yaml:"maximumEventAgeMinutes"`
	MinimumNormalizationCoverage float64       `json:"minimumNormalizationCoverage" yaml:"minimumNormalizationCoverage"`
	Requirements                 []Requirement `json:"requirements,omitempty" yaml:"requirements,omitempty"`
}

type Requirement struct {
	Platform     string `json:"platform" yaml:"platform"`
	SourceID     string `json:"sourceId,omitempty" yaml:"sourceId,omitempty"`
	Category     string `json:"category,omitempty" yaml:"category,omitempty"`
	MinimumCount int    `json:"minimumCount,omitempty" yaml:"minimumCount,omitempty"`
}

type Source struct {
	ID            string        `json:"id" yaml:"id"`
	Platform      string        `json:"platform" yaml:"platform"`
	Name          string        `json:"name" yaml:"name"`
	Category      string        `json:"category" yaml:"category"`
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	LastEventAt   *time.Time    `json:"lastEventAt,omitempty" yaml:"lastEventAt,omitempty"`
	RetentionDays int           `json:"retentionDays" yaml:"retentionDays"`
	Normalization Normalization `json:"normalization" yaml:"normalization"`
}

type Normalization struct {
	Standard        string  `json:"standard" yaml:"standard"`
	Schema          string  `json:"schema" yaml:"schema"`
	Version         string  `json:"version,omitempty" yaml:"version,omitempty"`
	CoveragePercent float64 `json:"coveragePercent" yaml:"coveragePercent"`
	Validated       bool    `json:"validated" yaml:"validated"`
}

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

type Check struct {
	Name     string `json:"name" yaml:"name"`
	Status   Status `json:"status" yaml:"status"`
	Message  string `json:"message" yaml:"message"`
	SourceID string `json:"sourceId,omitempty" yaml:"sourceId,omitempty"`
	Platform string `json:"platform,omitempty" yaml:"platform,omitempty"`
}

type SourceResult struct {
	ID        string  `json:"id" yaml:"id"`
	Platform  string  `json:"platform" yaml:"platform"`
	Compliant bool    `json:"compliant" yaml:"compliant"`
	Checks    []Check `json:"checks" yaml:"checks"`
}

type Summary struct {
	Sources          int `json:"sources" yaml:"sources"`
	CompliantSources int `json:"compliantSources" yaml:"compliantSources"`
	FailedChecks     int `json:"failedChecks" yaml:"failedChecks"`
	UnknownChecks    int `json:"unknownChecks" yaml:"unknownChecks"`
}

type Report struct {
	Compliant         bool              `json:"compliant" yaml:"compliant"`
	EvaluatedAt       time.Time         `json:"evaluatedAt" yaml:"evaluatedAt"`
	Policy            Policy            `json:"policy" yaml:"policy"`
	ExpectedStandards map[string]string `json:"expectedStandards" yaml:"expectedStandards"`
	Sources           []SourceResult    `json:"sources" yaml:"sources"`
	Requirements      []Check           `json:"requirements" yaml:"requirements"`
	Summary           Summary           `json:"summary" yaml:"summary"`
}
