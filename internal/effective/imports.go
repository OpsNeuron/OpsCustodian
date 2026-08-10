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
		processed := map[string]struct{}{}
		arguments := map[string]string{}
		state := newImportState(caller)
		compositionOrder := composeBreadthFirst(caller, assets, processed, arguments, state, &bom.Diagnostics)
		applySafeOutputControl(caller, state)
		if len(compositionOrder) > 0 {
			caller.Controls = append(caller.Controls, model.Control{Type: "importComposition", Value: compositionOrder})
		}
	}
	sort.Slice(bom.Diagnostics, func(i, j int) bool {
		return bom.Diagnostics[i].Path+bom.Diagnostics[i].Code+bom.Diagnostics[i].Message < bom.Diagnostics[j].Path+bom.Diagnostics[j].Code+bom.Diagnostics[j].Message
	})
}

type importTask struct {
	dependency model.Reference
	path       []string
}

type importState struct {
	mainSafeOutputs     map[string]struct{}
	importedSafeOutputs map[string]string
	safeOutputNames     map[string]struct{}
}

func newImportState(caller *model.Asset) *importState {
	state := &importState{mainSafeOutputs: map[string]struct{}{}, importedSafeOutputs: map[string]string{}, safeOutputNames: map[string]struct{}{}}
	for _, capability := range caller.Capabilities {
		if isSafeOutput(capability) {
			state.mainSafeOutputs[capability.Action] = struct{}{}
		}
	}
	return state
}

func composeBreadthFirst(root *model.Asset, assets map[string]*model.Asset, processed map[string]struct{}, arguments map[string]string, state *importState, diagnostics *[]model.Diagnostic) []string {
	queue := importTasks(root.Dependencies, []string{root.ID})
	var compositionOrder []string
	for len(queue) > 0 {
		task := queue[0]
		queue = queue[1:]
		dependency := task.dependency
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
		validateImportParameters(root, imported, dependency.Parameters, diagnostics)
		if previous, seen := arguments[imported.ID]; seen && previous != signature {
			*diagnostics = append(*diagnostics, diagnostic(root, "GHAW_IMPORT_PARAMETER_CONFLICT", "import "+imported.Name+" is used more than once with different parameters"))
			continue
		}
		arguments[imported.ID] = signature
		if containsString(task.path, imported.ID) {
			*diagnostics = append(*diagnostics, diagnostic(root, "GHAW_IMPORT_CYCLE", "import cycle reaches "+imported.Name))
			continue
		}
		if _, done := processed[imported.ID]; done {
			continue
		}
		validateImportedPermissions(root, imported, diagnostics)
		mergeImportable(root, imported, state, diagnostics)
		processed[imported.ID] = struct{}{}
		compositionOrder = append(compositionOrder, imported.Name)
		nextPath := append(append([]string(nil), task.path...), imported.ID)
		queue = append(queue, importTasks(imported.Dependencies, nextPath)...)
	}
	return compositionOrder
}

func importTasks(dependencies []model.Reference, path []string) []importTask {
	var result []importTask
	for _, dependency := range dependencies {
		if dependency.Type == "workflow" {
			result = append(result, importTask{dependency: dependency, path: path})
		}
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateImportParameters(caller, imported *model.Asset, parameters map[string]any, diagnostics *[]model.Diagnostic) {
	schema := importSchema(imported)
	if schema == nil {
		return
	}
	properties, _ := schema["properties"].(map[string]any)
	required := stringSet(schema["required"])
	for name := range required {
		if _, exists := parameters[name]; !exists {
			*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_PARAMETER_REQUIRED", "import "+imported.Name+" requires parameter "+name))
		}
	}
	additionalAllowed, specified := schema["additionalProperties"].(bool)
	for name, value := range parameters {
		property, declared := properties[name].(map[string]any)
		if !declared {
			if specified && !additionalAllowed {
				*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_PARAMETER_UNKNOWN", "import "+imported.Name+" does not declare parameter "+name))
			}
			continue
		}
		expected, _ := property["type"].(string)
		if expected != "" && !matchesJSONType(value, expected) {
			*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_PARAMETER_TYPE", fmt.Sprintf("import %s parameter %s must be %s", imported.Name, name, expected)))
			continue
		}
		if enum, exists := property["enum"].([]any); exists && !containsValue(enum, value) {
			*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_PARAMETER_ENUM", "import "+imported.Name+" parameter "+name+" is outside its allowed values"))
		}
	}
}

func importSchema(asset *model.Asset) map[string]any {
	for _, control := range asset.Controls {
		if control.Type != "importSchema" {
			continue
		}
		if value, ok := control.Value.(map[string]any); ok {
			return value
		}
	}
	return nil
}

func stringSet(value any) map[string]struct{} {
	result := map[string]struct{}{}
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if text, ok := item.(string); ok {
				result[text] = struct{}{}
			}
		}
	}
	return result
}

func matchesJSONType(value any, expected string) bool {
	switch expected {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		switch value.(type) {
		case int, int64, float64:
			return true
		}
		return false
	case "integer":
		switch number := value.(type) {
		case int, int64:
			return true
		case float64:
			return number == float64(int64(number))
		}
		return false
	case "array":
		_, ok := value.([]any)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "null":
		return value == nil
	default:
		return true
	}
}

func containsValue(values []any, candidate any) bool {
	candidateJSON, _ := json.Marshal(candidate)
	for _, value := range values {
		encoded, _ := json.Marshal(value)
		if string(encoded) == string(candidateJSON) {
			return true
		}
	}
	return false
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

func mergeImportable(caller, imported *model.Asset, state *importState, diagnostics *[]model.Diagnostic) {
	caller.Tools = append(caller.Tools, imported.Tools...)
	caller.Credentials = append(caller.Credentials, imported.Credentials...)
	for _, capability := range imported.Capabilities {
		if !isImportableCapability(capability) {
			continue
		}
		if isSafeOutput(capability) {
			if _, overridden := state.mainSafeOutputs[capability.Action]; overridden {
				continue
			}
			if owner, conflict := state.importedSafeOutputs[capability.Action]; conflict {
				message := fmt.Sprintf("safe output %s is declared by both imports %s and %s", safeOutputName(capability), owner, imported.Name)
				*diagnostics = append(*diagnostics, diagnostic(caller, "GHAW_IMPORT_SAFE_OUTPUT_CONFLICT", message))
				continue
			}
			state.importedSafeOutputs[capability.Action] = imported.Name
			state.safeOutputNames[safeOutputName(capability)] = struct{}{}
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
	return strings.HasPrefix(value, "network")
}

func isSafeOutput(capability model.Capability) bool {
	return strings.HasPrefix(capability.Action, "github.safe_output.")
}
func safeOutputName(capability model.Capability) string {
	return strings.TrimPrefix(capability.Action, "github.safe_output.")
}

func applySafeOutputControl(caller *model.Asset, state *importState) {
	if len(state.safeOutputNames) == 0 {
		return
	}
	index := -1
	names := map[string]struct{}{}
	for controlIndex, control := range caller.Controls {
		if control.Type != "safeOutputs" {
			continue
		}
		index = controlIndex
		for _, name := range controlStrings(control.Value) {
			names[name] = struct{}{}
		}
	}
	for name := range state.safeOutputNames {
		names[name] = struct{}{}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	if index >= 0 {
		caller.Controls[index].Value = result
		return
	}
	caller.Controls = append(caller.Controls, model.Control{Type: "safeOutputs", Value: result})
}

func controlStrings(value any) []string {
	switch values := value.(type) {
	case []string:
		return values
	case []any:
		var result []string
		for _, item := range values {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
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
