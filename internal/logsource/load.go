package logsource

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
	maxInventoryBytes = 1 << 20
	maxYAMLDepth      = 32
	maxYAMLNodes      = 10000
)

func LoadFile(path string) (Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return Inventory{}, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxInventoryBytes+1))
	if err != nil {
		return Inventory{}, fmt.Errorf("read log-source inventory: %w", err)
	}
	if len(data) > maxInventoryBytes {
		return Inventory{}, fmt.Errorf("log-source inventory exceeds %d byte limit", maxInventoryBytes)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return Inventory{}, fmt.Errorf("parse log-source inventory: %w", err)
	}
	if err := inspectYAML(&node, 0, new(int)); err != nil {
		return Inventory{}, err
	}

	var inventory Inventory
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&inventory); err != nil {
		return Inventory{}, fmt.Errorf("decode log-source inventory: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Inventory{}, errors.New("log-source inventory must contain exactly one YAML document")
		}
		return Inventory{}, fmt.Errorf("decode trailing log-source inventory YAML: %w", err)
	}
	return inventory, nil
}

func inspectYAML(node *yaml.Node, depth int, count *int) error {
	(*count)++
	if *count > maxYAMLNodes {
		return errors.New("log-source inventory YAML exceeds node limit")
	}
	if depth > maxYAMLDepth {
		return errors.New("log-source inventory YAML exceeds nesting limit")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML anchors and aliases are not permitted in log-source inventories")
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("custom YAML tag %q is not permitted in log-source inventories", node.Tag)
	}
	for _, child := range node.Content {
		if err := inspectYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
