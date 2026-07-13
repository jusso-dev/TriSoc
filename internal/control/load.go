package control

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxControlBytes = 1 << 20
	maxYAMLDepth    = 32
	maxYAMLNodes    = 10000
)

func LoadPaths(paths ...string) ([]Control, ValidationResult) {
	files, discoveryIssues := discoverFiles(paths)
	result := ValidationResult{Files: len(files), Issues: discoveryIssues}
	if result.Issues == nil {
		result.Issues = make([]ValidationIssue, 0)
	}
	controls := make([]Control, 0, len(files))
	seen := make(map[string]string)
	validator := NewValidator()

	for _, path := range files {
		c, err := LoadFile(path)
		if err != nil {
			result.Issues = append(result.Issues, ValidationIssue{Path: path, Severity: "error", Message: err.Error()})
			continue
		}
		for _, issue := range validator.Validate(c) {
			issue.Path = path + issue.Path
			result.Issues = append(result.Issues, issue)
		}
		key := c.Metadata.ID + "@" + c.Metadata.Version
		if previous, ok := seen[key]; ok {
			result.Issues = append(result.Issues, ValidationIssue{Path: path, Severity: "error", Message: fmt.Sprintf("duplicate control %s (already loaded from %s)", key, previous)})
		} else {
			seen[key] = path
		}
		controls = append(controls, c)
	}
	result.Controls = len(controls)
	result.Valid = len(result.Issues) == 0
	return controls, result
}

func LoadFile(path string) (Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return Control{}, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxControlBytes+1))
	if err != nil {
		return Control{}, fmt.Errorf("read control: %w", err)
	}
	if len(data) > maxControlBytes {
		return Control{}, fmt.Errorf("control exceeds %d byte limit", maxControlBytes)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return Control{}, fmt.Errorf("parse YAML: %w", err)
	}
	if err := inspectYAML(&node, 0, new(int)); err != nil {
		return Control{}, err
	}

	var c Control
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Control{}, fmt.Errorf("decode control: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Control{}, errors.New("control file must contain exactly one YAML document")
		}
		return Control{}, fmt.Errorf("decode trailing YAML: %w", err)
	}
	return c, nil
}

func inspectYAML(node *yaml.Node, depth int, count *int) error {
	*count++
	if *count > maxYAMLNodes {
		return errors.New("control YAML exceeds node limit")
	}
	if depth > maxYAMLDepth {
		return errors.New("control YAML exceeds nesting limit")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML anchors and aliases are not permitted in controls")
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("custom YAML tag %q is not permitted", node.Tag)
	}
	for _, child := range node.Content {
		if err := inspectYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func discoverFiles(paths []string) ([]string, []ValidationIssue) {
	if len(paths) == 0 {
		paths = []string{"controls"}
	}
	var files []string
	var issues []ValidationIssue
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			issues = append(issues, ValidationIssue{Path: path, Severity: "error", Message: err.Error()})
			continue
		}
		if !info.IsDir() {
			if isControlFile(path) {
				files = append(files, path)
			} else {
				issues = append(issues, ValidationIssue{Path: path, Severity: "error", Message: "control files must use .yaml or .yml"})
			}
			continue
		}
		err = filepath.WalkDir(path, func(item string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !entry.IsDir() && isControlFile(item) {
				files = append(files, item)
			}
			return nil
		})
		if err != nil {
			issues = append(issues, ValidationIssue{Path: path, Severity: "error", Message: err.Error()})
		}
	}
	sort.Strings(files)
	return files, issues
}

func isControlFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
