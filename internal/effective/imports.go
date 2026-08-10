package effective

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

// ComposeImports applies the conservative, security-relevant subset of gh-aw
// import composition to runnable workflows. Repository permissions are checked
// but never inherited because gh-aw requires the caller to declare them.
func ComposeImports(bom *model.AgentBOM) {
	assets := map[string]*model.Asset{}
	for index := range bom.Assets {
		asset := &bom.Assets[index]
		assets[lookupKey(asset.Type, asset.Name)] = asset
	}
	for index := range bom.Assets {
		caller := &bom.Assets[index]
		if caller.Type != "agent" || caller.Runtime == nil || caller.Runtime.Type != "github-agentic-workflow" {
			continue
		}
		active := map[string]struct{}{caller.ID: {}}
		processed := map[string]struct{}{}
		arguments := map[string]string{}
		compose(caller, caller, assets, active, processed, arguments, &bom.Diagnostics)
	}
	sort.Slice(bom.Diagnostics, func(i, j int) bool {
		return bom.Diagnostics[i].Path+bom.Diagnostics[i].Code+bom.Diagnostics[i].Message < bom.Diagnostics[j].Path+bom.Diagnostics[j].Code+bom.Diagnostics[j].Message
	})
}

func compose(root, current *model.Asset, assets map[string]*model.Asset, active, processed map[string]struct{}, arguments map[string]string, diagnostics *[]model.Diagnostic) {
	for _, dependency := range current.Dependencies {
		if dependency.Type != "workflow" {
			continue
		}
		imported, exists := assets[lookupKey("workflow", dependency.Reference)]
		if !exists {
			if !dependency.Optional && isLocalImport(dependency.Locator) {
				*diagnostics = append(*diagnostics, diagnostic(root, "GHAW_IMPORT_UNRESOLVED", "required local import was not discovered: "+dependency.Locator))
			}
			continue
		}
		signature := parameterSignature(dependency.Parameters)
		if previous, seen := arguments[imported.ID]; seen && previous != signature {
			*diagnostics = append(*diagnostics, diagnostic(root, "GHAW_IMPORT_PARAMETER_CONFLICT", "import "+imported.Name+" is used more than once with different parameters"))
			continue
		}
		arguments[imported.ID] = signature
		if _, seen := active[imported.ID]; seen {
			*diagnostics = append(*diagnostics, diagnostic(root, "GHAW_IMPORT_CYCLE", "import cycle reaches "+imported.Name))
			continue
		}
		if _, done := processed[imported.ID]; done {
			continue
		}
		active[imported.ID] = struct{}{}
		validateImportedPermissions(root, imported, diagnostics)
		mergeImportable(root, imported)
		compose(root, imported, assets, active, processed, arguments, diagnostics)
		delete(active, imported.ID)
		processed[imported.ID] = struct{}{}
	}
}

func parameterSignature(parameters map[string]any) string {
	value, _ := json.Marshal(parameters)
	return string(value)
}

func isLocalImport(locator string) bool {
	if locator == "" {
		return false
	}
	return strings.LastIndex(locator, "@") <= strings.LastIndex(locator, "/")
}

func validateImportedPermissions(caller, imported *model.Asset, diagnostics *[]model.Diagnostic) {
	for _, required := range imported.Capabilities {
		if !isRepositoryPermission(required) {
			continue
		}
		if capabilityCovers(caller.Capabilities, required) {
			continue
		}
		message := fmt.Sprintf("import %s requires %s=%s but the caller does not declare sufficient permission", imported.Name, required.Action, required.Effect)
		*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_PERMISSION_UNSATISFIED", message))
	}
}

func mergeImportable(caller, imported *model.Asset) {
	caller.Tools = append(caller.Tools, imported.Tools...)
	caller.Credentials = append(caller.Credentials, imported.Credentials...)
	for _, capability := range imported.Capabilities {
		if !isImportableCapability(capability) {
			continue
		}
		caller.Capabilities = append(caller.Capabilities, capability)
		copyEvidence(caller, imported, capability.EvidenceIDs)
	}
	for _, control := range imported.Controls {
		if isImportableControl(control.Type) {
			caller.Controls = append(caller.Controls, control)
		}
	}
}

func isRepositoryPermission(capability model.Capability) bool {
	return strings.HasPrefix(capability.Action, "github.") && !strings.HasPrefix(capability.Action, "github.safe_output.")
}

func isImportableCapability(capability model.Capability) bool {
	return strings.HasPrefix(capability.Action, "github.safe_output.") || capability.Action == "network.connect" || capability.Action == "shell.execute" || capability.Action == "filesystem.modify"
}

func isImportableControl(value string) bool {
	return value == "safeOutputs" || strings.HasPrefix(value, "network")
}

func capabilityCovers(values []model.Capability, required model.Capability) bool {
	for _, candidate := range values {
		if candidate.Action != required.Action && candidate.Action != "github.repository.*" {
			continue
		}
		if effectRank(candidate.Effect) >= effectRank(required.Effect) {
			return true
		}
	}
	return false
}

func effectRank(value string) int {
	switch value {
	case "read":
		return 1
	case "write":
		return 2
	case "delete":
		return 3
	case "admin":
		return 4
	default:
		return 0
	}
}

func copyEvidence(caller, imported *model.Asset, wantedIDs []string) {
	wanted := map[string]struct{}{}
	for _, id := range wantedIDs {
		wanted[id] = struct{}{}
	}
	existing := map[string]struct{}{}
	for _, evidence := range caller.Evidence {
		existing[evidence.ID] = struct{}{}
	}
	for _, evidence := range imported.Evidence {
		if len(wanted) > 0 {
			if _, exists := wanted[evidence.ID]; !exists {
				continue
			}
		}
		if _, exists := existing[evidence.ID]; exists {
			continue
		}
		caller.Evidence = append(caller.Evidence, evidence)
		existing[evidence.ID] = struct{}{}
	}
}

func diagnostic(asset *model.Asset, code, message string) model.Diagnostic {
	return model.Diagnostic{Severity: "warning", Code: code, Path: asset.Source.Path, Parser: "github-agentic-workflows", Message: message}
}

func lookupKey(kind, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
}
