package normalize

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

func BOM(bom *model.AgentBOM) {
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		asset.Owners = uniqueStrings(asset.Owners)
		asset.Tools = uniqueReferences(asset.Tools)
		asset.Dependencies = uniqueReferences(asset.Dependencies)
		asset.Credentials = uniqueCredentials(asset.Credentials)
		for capabilityIndex := range asset.Capabilities {
			capability := &asset.Capabilities[capabilityIndex]
			capability.Action = normalizeAction(capability.Action)
			capability.Effect = strings.ToLower(strings.TrimSpace(capability.Effect))
			capability.Resource = strings.TrimSpace(strings.ReplaceAll(capability.Resource, "\\", "/"))
			capability.Environment = strings.ToLower(strings.TrimSpace(capability.Environment))
			capability.EvidenceIDs = uniqueStrings(capability.EvidenceIDs)
			if capability.Scope == nil {
				capability.Scope = inferScope(capability.Resource)
			} else {
				capability.Scope.Kind = strings.ToLower(strings.TrimSpace(capability.Scope.Kind))
				capability.Scope.Values = normalizedPath(capability.Scope.Values)
			}
		}
		asset.Capabilities = uniqueCapabilities(asset.Capabilities)
		sort.Slice(asset.Capabilities, func(i, j int) bool {
			return capabilitySortKey(asset.Capabilities[i]) < capabilitySortKey(asset.Capabilities[j])
		})
	}
}

func uniqueCapabilities(values []model.Capability) []model.Capability {
	seen := map[string]model.Capability{}
	for _, value := range values {
		key := capabilitySortKey(value) + "\x00" + scopeKey(value.Scope)
		if existing, exists := seen[key]; exists {
			existing.EvidenceIDs = uniqueStrings(append(existing.EvidenceIDs, value.EvidenceIDs...))
			seen[key] = existing
			continue
		}
		seen[key] = value
	}
	result := make([]model.Capability, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	return result
}

func scopeKey(value *model.Scope) string {
	if value == nil {
		return ""
	}
	return value.Kind + "\x00" + strings.Join(value.Values, "\x00") + fmt.Sprintf("\x00%t", value.Wildcard)
}

func ScopeExpanded(before, after *model.Scope) (bool, string) {
	if before == nil || after == nil || before.Kind != after.Kind {
		return false, ""
	}
	if !before.Wildcard && after.Wildcard {
		return true, "scope introduced wildcard access"
	}
	if equalStrings(before.Values, after.Values) {
		return false, ""
	}
	if len(after.Values) < len(before.Values) && isPrefix(after.Values, before.Values) {
		return true, "scope broadened from a specific child to its parent"
	}
	return false, ""
}

func EffectRank(effect string) int {
	switch effect {
	case "observe":
		return 1
	case "read":
		return 2
	case "execute":
		return 3
	case "write":
		return 4
	case "delete":
		return 5
	case "admin":
		return 6
	default:
		return 0
	}
}

func inferScope(resource string) *model.Scope {
	wildcard := strings.Contains(resource, "*")
	switch {
	case strings.HasPrefix(resource, "github:organization:"):
		return &model.Scope{Kind: "organization", Values: splitValues(strings.TrimPrefix(resource, "github:organization:")), Wildcard: wildcard}
	case strings.HasPrefix(resource, "github:"):
		value := strings.TrimPrefix(resource, "github:")
		return &model.Scope{Kind: "repository", Values: splitValues(value), Wildcard: wildcard}
	case strings.HasPrefix(resource, "kubernetes:"):
		return &model.Scope{Kind: "kubernetes", Values: splitValues(strings.TrimPrefix(resource, "kubernetes:")), Wildcard: wildcard}
	case strings.HasPrefix(resource, "network:"):
		return &model.Scope{Kind: "network", Values: splitValues(strings.TrimPrefix(resource, "network:")), Wildcard: wildcard}
	case strings.HasPrefix(resource, "workspace:"):
		return &model.Scope{Kind: "workspace", Values: splitValues(strings.TrimPrefix(resource, "workspace:")), Wildcard: wildcard}
	case strings.HasPrefix(resource, "mcp:"):
		return &model.Scope{Kind: "mcp-server", Values: splitValues(strings.TrimPrefix(resource, "mcp:")), Wildcard: wildcard}
	default:
		return &model.Scope{Kind: "unknown", Values: splitValues(resource), Wildcard: wildcard}
	}
}

func normalizeAction(value string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), ".")
	for index := range parts {
		parts[index] = strings.ReplaceAll(strings.TrimSpace(parts[index]), "-", "_")
	}
	return strings.Join(parts, ".")
}

func splitValues(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == ':' })
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && part != "*" {
			result = append(result, part)
		}
	}
	return result
}

func normalizedPath(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[strings.ToLower(value)] = value
		}
	}
	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueReferences(values []model.Reference) []model.Reference {
	seen := map[string]model.Reference{}
	for _, value := range values {
		value.Type, value.Reference = strings.TrimSpace(value.Type), strings.TrimSpace(value.Reference)
		if value.Type != "" && value.Reference != "" {
			key := referenceSortKey(value)
			if _, exists := seen[key]; !exists {
				seen[key] = value
			}
		}
	}
	result := make([]model.Reference, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type == result[j].Type && result[i].Order != result[j].Order {
			return result[i].Order < result[j].Order
		}
		return referenceSortKey(result[i]) < referenceSortKey(result[j])
	})
	return result
}

func referenceSortKey(value model.Reference) string {
	parameters, _ := json.Marshal(value.Parameters)
	return strings.ToLower(value.Type) + "\x00" + strings.ToLower(value.Reference) + "\x00" + strings.ToLower(value.Locator) + fmt.Sprintf("\x00%t\x00", value.Optional) + string(parameters)
}

func uniqueCredentials(values []model.CredentialReference) []model.CredentialReference {
	seen := map[string]model.CredentialReference{}
	for _, value := range values {
		if value.Type != "" && value.Reference != "" {
			seen[strings.ToLower(value.Type)+"\x00"+strings.ToLower(value.Reference)] = value
		}
	}
	result := make([]model.CredentialReference, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Type+result[i].Reference < result[j].Type+result[j].Reference })
	return result
}

func capabilitySortKey(value model.Capability) string {
	return value.Action + "\x00" + value.Resource + "\x00" + value.Effect + "\x00" + value.Environment
}
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func isPrefix(prefix, value []string) bool {
	if len(prefix) > len(value) {
		return false
	}
	for index := range prefix {
		if prefix[index] != value[index] {
			return false
		}
	}
	return true
}
