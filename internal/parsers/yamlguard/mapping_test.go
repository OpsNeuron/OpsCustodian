package yamlguard

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateMappingKeys(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "unique nested mappings", content: "root:\n  first: 1\n  second: 2\n"},
		{name: "duplicate YAML key", content: "root:\n  value: 1\n  value: 2\n", wantErr: `duplicate mapping key "value"`},
		{name: "duplicate JSON key", content: `{"root":{"value":1,"value":2}}`, wantErr: `duplicate mapping key "value"`},
		{name: "non scalar key", content: "? [one, two]\n: value\n", wantErr: "must be a scalar"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document yaml.Node
			if err := yaml.Unmarshal([]byte(test.content), &document); err != nil {
				t.Fatalf("yaml.Unmarshal() error = %v", err)
			}
			err := ValidateMappingKeys(&document)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateMappingKeys() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateMappingKeys() error = %v, expected %q", err, test.wantErr)
			}
		})
	}
}
