// Package evidence creates redacted, deterministic evidence records.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Record struct {
	Provider          string         `json:"provider"`
	Operation         string         `json:"operation"`
	Query             string         `json:"query,omitempty"`
	Scope             string         `json:"scope"`
	ResourceIDs       []string       `json:"resourceIds"`
	ObservedAt        time.Time      `json:"observedAt"`
	CollectorIdentity string         `json:"collectorIdentity"`
	Configuration     map[string]any `json:"configuration"`
	EvaluatorVersion  string         `json:"evaluatorVersion"`
	ControlVersion    string         `json:"controlVersion"`
	Result            string         `json:"result"`
	Explanation       string         `json:"explanation"`
	ValidUntil        time.Time      `json:"validUntil"`
}

var sensitiveKey = regexp.MustCompile(`(?i)(authorization|password|passwd|secret|token|api.?key|access.?key|private.?key|client.?secret|credential|cookie)`)
var bearerValue = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)

func Hash(record Record) (string, []byte, error) {
	redacted := Redact(record)
	canonical, err := json.Marshal(redacted)
	if err != nil {
		return "", nil, fmt.Errorf("marshal redacted evidence: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), canonical, nil
}

func Redact(record Record) Record {
	clone := record
	clone.Query = redactString(clone.Query)
	clone.CollectorIdentity = redactString(clone.CollectorIdentity)
	clone.Explanation = redactString(clone.Explanation)
	clone.Configuration = redactMap(clone.Configuration)
	return clone
}

func redactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey.MatchString(key) {
			out[key] = "[REDACTED]"
			continue
		}
		out[key] = redactValue(value)
	}
	return out
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactValue(item)
		}
		return out
	case string:
		return redactString(typed)
	default:
		return value
	}
}

func redactString(value string) string {
	value = bearerValue.ReplaceAllString(value, "$1 [REDACTED]")
	if sensitiveKey.MatchString(value) && strings.Contains(value, "=") {
		parts := strings.SplitN(value, "=", 2)
		return parts[0] + "=[REDACTED]"
	}
	return value
}
