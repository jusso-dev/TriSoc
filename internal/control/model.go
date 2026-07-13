// Package control defines and validates TriSOC Attestor's declarative controls.
package control

import "time"

const (
	APIVersion = "attestor.trisoc.io/v1"
	Kind       = "Control"
)

type Control struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

type Metadata struct {
	ID         string   `yaml:"id" json:"id"`
	Title      string   `yaml:"title" json:"title"`
	Vendor     string   `yaml:"vendor" json:"vendor"`
	Product    string   `yaml:"product" json:"product"`
	Service    string   `yaml:"service" json:"service"`
	Version    string   `yaml:"version" json:"version"`
	Status     string   `yaml:"status" json:"status"`
	Tags       []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	ReplacedBy string   `yaml:"supersedingControlId,omitempty" json:"supersedingControlId,omitempty"`
}

type Spec struct {
	Classification      string               `yaml:"classification" json:"classification"`
	Severity            string               `yaml:"severity" json:"severity"`
	Scopes              []string             `yaml:"scopes" json:"scopes"`
	Applicability       *Applicability       `yaml:"applicability,omitempty" json:"applicability,omitempty"`
	Source              Source               `yaml:"source" json:"source"`
	RequiredPermissions []string             `yaml:"requiredPermissions" json:"requiredPermissions"`
	Expected            map[string]any       `yaml:"expected" json:"expected"`
	Collector           Collector            `yaml:"collector" json:"collector"`
	Evaluator           Evaluator            `yaml:"evaluator" json:"evaluator"`
	Explanation         Explanation          `yaml:"explanation" json:"explanation"`
	Remediation         Remediation          `yaml:"remediation" json:"remediation"`
	Evidence            EvidenceRequirements `yaml:"evidence" json:"evidence"`
	Freshness           string               `yaml:"maximumEvidenceAge" json:"maximumEvidenceAge"`
	References          []Reference          `yaml:"references,omitempty" json:"references,omitempty"`
	Drift               *Drift               `yaml:"drift,omitempty" json:"drift,omitempty"`
}

type Applicability struct {
	All []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Condition `yaml:"any,omitempty" json:"any,omitempty"`
}

type Condition struct {
	Field    string `yaml:"field" json:"field"`
	Operator string `yaml:"operator" json:"operator"`
	Value    any    `yaml:"value" json:"value"`
}

type Source struct {
	VendorControlID string     `yaml:"vendorControlId,omitempty" json:"vendorControlId,omitempty"`
	Title           string     `yaml:"title" json:"title"`
	URL             string     `yaml:"url" json:"url"`
	PublishedAt     *time.Time `yaml:"publishedAt,omitempty" json:"publishedAt,omitempty"`
	RetrievedAt     time.Time  `yaml:"retrievedAt" json:"retrievedAt"`
	Version         string     `yaml:"version,omitempty" json:"version,omitempty"`
	ContentHash     string     `yaml:"contentHash" json:"contentHash"`
}

type Collector struct {
	Provider   string         `yaml:"provider" json:"provider"`
	Operation  string         `yaml:"operation" json:"operation"`
	Parameters map[string]any `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type Evaluator struct {
	Type       string `yaml:"type" json:"type"`
	Expression string `yaml:"expression" json:"expression"`
}

type Explanation struct {
	Technical    string `yaml:"technical" json:"technical"`
	PlainEnglish string `yaml:"plainEnglish" json:"plainEnglish"`
}

type Remediation struct {
	Risk          string `yaml:"risk" json:"risk"`
	Automatic     string `yaml:"automatic" json:"automatic"`
	PlanGenerator string `yaml:"planGenerator,omitempty" json:"planGenerator,omitempty"`
	Guidance      string `yaml:"guidance" json:"guidance"`
	CostImpact    string `yaml:"costImpact" json:"costImpact"`
	Destructive   bool   `yaml:"destructive" json:"destructive"`
}

type EvidenceRequirements struct {
	Fields []string `yaml:"requiredFields" json:"requiredFields"`
	Redact []string `yaml:"redact,omitempty" json:"redact,omitempty"`
}

type Reference struct {
	Title string `yaml:"title" json:"title"`
	URL   string `yaml:"url" json:"url"`
}

type Drift struct {
	Compare []string `yaml:"compare,omitempty" json:"compare,omitempty"`
	Ignore  []string `yaml:"ignore,omitempty" json:"ignore,omitempty"`
}

type Bundle struct {
	Controls []Control `json:"controls" yaml:"controls"`
}

type ValidationIssue struct {
	Path     string `json:"path" yaml:"path"`
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}

type ValidationResult struct {
	Valid    bool              `json:"valid" yaml:"valid"`
	Files    int               `json:"files" yaml:"files"`
	Controls int               `json:"controls" yaml:"controls"`
	Issues   []ValidationIssue `json:"issues" yaml:"issues"`
}
