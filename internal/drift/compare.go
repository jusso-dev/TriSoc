// Package drift compares canonical provider snapshots while excluding volatile
// observation metadata.
package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

type Change struct {
	Path     string `json:"path" yaml:"path"`
	Previous any    `json:"previous" yaml:"previous"`
	Current  any    `json:"current" yaml:"current"`
}
type Comparison struct {
	Drift        bool     `json:"drift" yaml:"drift"`
	PreviousHash string   `json:"previousHash" yaml:"previousHash"`
	CurrentHash  string   `json:"currentHash" yaml:"currentHash"`
	Changes      []Change `json:"changes" yaml:"changes"`
}

func Compare(previous, current any, ignorePaths []string) (Comparison, error) {
	a, err := normalise(previous)
	if err != nil {
		return Comparison{}, err
	}
	b, err := normalise(current)
	if err != nil {
		return Comparison{}, err
	}
	for _, path := range ignorePaths {
		remove(a, path)
		remove(b, path)
	}
	ah, err := hash(a)
	if err != nil {
		return Comparison{}, err
	}
	bh, err := hash(b)
	if err != nil {
		return Comparison{}, err
	}
	out := Comparison{Drift: ah != bh, PreviousHash: ah, CurrentHash: bh, Changes: []Change{}}
	diff("", a, b, &out.Changes)
	sort.Slice(out.Changes, func(i, j int) bool { return out.Changes[i].Path < out.Changes[j].Path })
	return out, nil
}
func normalise(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func hash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func remove(root map[string]any, path string) {
	parts := strings.Split(path, ".")
	current := root
	for i, part := range parts {
		if i == len(parts)-1 {
			delete(current, part)
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
}
func diff(path string, a, b any, changes *[]Change) {
	if reflect.DeepEqual(a, b) {
		return
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		for key := range keys {
			next := key
			if path != "" {
				next = path + "." + key
			}
			diff(next, am[key], bm[key], changes)
		}
		return
	}
	*changes = append(*changes, Change{Path: path, Previous: a, Current: b})
}
func CanonicalHash(value any, ignorePaths []string) (string, error) {
	normal, err := normalise(value)
	if err != nil {
		return "", fmt.Errorf("normalise configuration: %w", err)
	}
	for _, path := range ignorePaths {
		remove(normal, path)
	}
	return hash(normal)
}
