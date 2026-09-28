package yamlguard

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ValidateMappingKeys rejects ambiguous mappings before a parser interprets
// them. Duplicate and non-scalar keys can otherwise be resolved differently
// by YAML/JSON tooling and produce a misleading security inventory.
func ValidateMappingKeys(node *yaml.Node) error {
	return validateMappingKeys(node, map[*yaml.Node]struct{}{})
}

func validateMappingKeys(node *yaml.Node, visited map[*yaml.Node]struct{}) error {
	if node == nil {
		return nil
	}
	if _, ok := visited[node]; ok {
		return nil
	}
	visited[node] = struct{}{}

	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateMappingKeys(child, visited); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return fmt.Errorf("mapping key at line %d must be a scalar", key.Line)
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate mapping key %q at line %d", key.Value, key.Line)
			}
			seen[key.Value] = struct{}{}
			if err := validateMappingKeys(node.Content[index+1], visited); err != nil {
				return err
			}
		}
	case yaml.AliasNode:
		return validateMappingKeys(node.Alias, visited)
	}
	return nil
}
