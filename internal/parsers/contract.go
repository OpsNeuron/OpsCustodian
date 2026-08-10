package parsers

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

var parserNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func ValidateRegistry(values []Parser) error {
	seen := map[string]struct{}{}
	for _, parser := range values {
		if parser == nil {
			return fmt.Errorf("parser registry contains a nil parser")
		}
		name := parser.Name()
		if !parserNamePattern.MatchString(name) {
			return fmt.Errorf("parser name %q must match %s", name, parserNamePattern.String())
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("parser name %q is registered more than once", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func ValidateResult(parser Parser, artifact discovery.Artifact, assets []model.Asset) ([]model.Asset, []model.Diagnostic) {
	valid := make([]model.Asset, 0, len(assets))
	var diagnostics []model.Diagnostic
	for _, asset := range assets {
		violations := assetViolations(parser.Name(), artifact.RelPath, asset)
		if len(violations) == 0 {
			valid = append(valid, asset)
			continue
		}
		diagnostics = append(diagnostics, model.Diagnostic{
			Severity: "error", Code: "parser-contract-violation", Path: artifact.RelPath,
			Parser: parser.Name(), Message: strings.Join(violations, "; "),
		})
	}
	return valid, diagnostics
}

func assetViolations(parserName, artifactPath string, asset model.Asset) []string {
	var result []string
	if strings.TrimSpace(asset.ID) == "" {
		result = append(result, "asset id is empty")
	}
	if strings.TrimSpace(asset.Name) == "" {
		result = append(result, "asset name is empty")
	}
	allowedTypes := map[string]struct{}{"agent": {}, "workflow": {}, "mcp-server": {}, "skill": {}, "instruction-set": {}, "workload": {}, "identity": {}, "authorization-role": {}, "authorization-binding": {}}
	if _, allowed := allowedTypes[asset.Type]; !allowed {
		result = append(result, "unsupported asset type "+asset.Type)
	}
	if asset.Source.Path != artifactPath {
		result = append(result, fmt.Sprintf("source path %q does not match artifact %q", asset.Source.Path, artifactPath))
	}
	if len(asset.Evidence) == 0 {
		result = append(result, "asset has no evidence")
	}
	evidenceIDs := map[string]struct{}{}
	for _, evidence := range asset.Evidence {
		if evidence.ID == "" {
			result = append(result, "evidence id is empty")
			continue
		}
		if _, exists := evidenceIDs[evidence.ID]; exists {
			result = append(result, "duplicate evidence id "+evidence.ID)
		}
		evidenceIDs[evidence.ID] = struct{}{}
		if evidence.Parser != parserName {
			result = append(result, fmt.Sprintf("evidence %s names parser %q instead of %q", evidence.ID, evidence.Parser, parserName))
		}
		if evidence.Path != artifactPath {
			result = append(result, fmt.Sprintf("evidence %s path %q does not match artifact", evidence.ID, evidence.Path))
		}
	}
	for _, capability := range asset.Capabilities {
		for _, evidenceID := range capability.EvidenceIDs {
			if _, exists := evidenceIDs[evidenceID]; !exists {
				result = append(result, "capability references unknown evidence "+evidenceID)
			}
		}
	}
	for _, credential := range asset.Credentials {
		if credential.ValueCaptured {
			result = append(result, "credential "+credential.Reference+" captures a value")
		}
	}
	sort.Strings(result)
	return result
}
