package maturity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxAssessmentBytes = 1 << 20
	maxYAMLDepth       = 32
	maxYAMLNodes       = 20000
)

func LoadFile(path string) (Assessment, error) {
	f, err := os.Open(path)
	if err != nil {
		return Assessment{}, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxAssessmentBytes+1))
	if err != nil {
		return Assessment{}, fmt.Errorf("read SOC maturity assessment: %w", err)
	}
	if len(data) > maxAssessmentBytes {
		return Assessment{}, fmt.Errorf("SOC maturity assessment exceeds %d byte limit", maxAssessmentBytes)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return Assessment{}, fmt.Errorf("parse SOC maturity assessment: %w", err)
	}
	if err := inspectYAML(&node, 0, new(int)); err != nil {
		return Assessment{}, err
	}

	var assessment Assessment
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&assessment); err != nil {
		return Assessment{}, fmt.Errorf("decode SOC maturity assessment: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Assessment{}, errors.New("SOC maturity assessment must contain exactly one YAML document")
		}
		return Assessment{}, fmt.Errorf("decode trailing SOC maturity assessment YAML: %w", err)
	}
	return assessment, nil
}

func inspectYAML(node *yaml.Node, depth int, count *int) error {
	(*count)++
	if *count > maxYAMLNodes {
		return errors.New("SOC maturity assessment YAML exceeds node limit")
	}
	if depth > maxYAMLDepth {
		return errors.New("SOC maturity assessment YAML exceeds nesting limit")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML anchors and aliases are not permitted in SOC maturity assessments")
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("custom YAML tag %q is not permitted in SOC maturity assessments", node.Tag)
	}
	for _, child := range node.Content {
		if err := inspectYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
