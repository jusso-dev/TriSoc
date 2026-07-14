// Package providers defines provider-neutral discovery contracts without erasing
// provider-specific evidence.
package providers

import "time"

type Scope struct {
	Provider    string            `json:"provider" yaml:"provider"`
	ID          string            `json:"id" yaml:"id"`
	Type        string            `json:"type" yaml:"type"`
	DisplayName string            `json:"displayName" yaml:"displayName"`
	Region      string            `json:"region,omitempty" yaml:"region,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type ConnectionStatus struct {
	Provider           string    `json:"provider" yaml:"provider"`
	Identity           string    `json:"identity" yaml:"identity"`
	SuccessfulScopes   []string  `json:"successfulScopes" yaml:"successfulScopes"`
	InaccessibleScopes []string  `json:"inaccessibleScopes" yaml:"inaccessibleScopes"`
	MissingPermissions []string  `json:"missingPermissions" yaml:"missingPermissions"`
	ExpiresAt          time.Time `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`
}
