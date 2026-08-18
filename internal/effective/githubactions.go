package effective

import (
	"path"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/normalize"
)

const maxReusableWorkflowDepth = 10

type reusableWorkflowEdge struct {
	caller int
	callee int
	call   model.GitHubReusableWorkflowCall
}

// ComposeGitHubReusableWorkflows resolves same-revision workflow calls and
// calculates the permission and secret envelope across nested call chains.
// External calls intentionally remain unresolved because scanning is offline.
func ComposeGitHubReusableWorkflows(bom *model.AgentBOM) {
	byPath := map[string]int{}
	for i := range bom.Assets {
		if bom.Assets[i].Type == "workflow" {
			byPath[reusableWorkflowPath(bom.Assets[i].Source.Path)] = i
		}
	}

	edges := map[int][]reusableWorkflowEdge{}
	for caller := range bom.Assets {
		asset := &bom.Assets[caller]
		for controlIndex := range asset.Controls {
			control := &asset.Controls[controlIndex]
			if control.Type != "githubReusableWorkflowCalls" {
				continue
			}
			calls, ok := control.Value.([]model.GitHubReusableWorkflowCall)
			if !ok {
				continue
			}
			for callIndex := range calls {
				call := &calls[callIndex]
				if !call.Local {
					continue
				}
				callee, exists := byPath[reusableWorkflowPath(call.Reference)]
				if !exists {
					call.Resolution = "local-unresolved"
					bom.Diagnostics = append(bom.Diagnostics, model.Diagnostic{
						Severity: "warning", Code: "GITHUB_REUSABLE_WORKFLOW_UNRESOLVED",
						Path: asset.Source.Path, Parser: "github-actions-effective",
						Message: "local reusable workflow target was not found: " + call.Reference,
					})
					continue
				}
				call.Resolution = "local-resolved"
				edges[caller] = append(edges[caller], reusableWorkflowEdge{caller: caller, callee: callee, call: *call})
			}
			control.Value = calls
		}
	}

	for caller := range edges {
		sort.Slice(edges[caller], func(i, j int) bool {
			left, right := edges[caller][i], edges[caller][j]
			if left.call.Job != right.call.Job {
				return left.call.Job < right.call.Job
			}
			return bom.Assets[left.callee].ID < bom.Assets[right.callee].ID
		})
	}

	diagnostics := map[string]model.Diagnostic{}
	for root := range bom.Assets {
		if len(edges[root]) == 0 {
			continue
		}
		var hops []model.GitHubReusableWorkflowHop
		walkReusableWorkflows(bom, edges, root, root, nil, "caller-visible", []int{root}, &hops, diagnostics)
		if len(hops) > 0 {
			bom.Assets[root].Controls = append(bom.Assets[root].Controls, model.Control{
				Type: "githubReusableWorkflowComposition", Value: hops,
			})
		}
	}
	for _, diagnostic := range diagnostics {
		bom.Diagnostics = append(bom.Diagnostics, diagnostic)
	}
}

func walkReusableWorkflows(bom *model.AgentBOM, edges map[int][]reusableWorkflowEdge, root, caller int, inheritedPermissions []model.Capability, availableSecrets string, stack []int, hops *[]model.GitHubReusableWorkflowHop, diagnostics map[string]model.Diagnostic) {
	for _, edge := range edges[caller] {
		depth := len(stack)
		if depth > maxReusableWorkflowDepth {
			addReusableDiagnostic(diagnostics, bom.Assets[root], "GITHUB_REUSABLE_WORKFLOW_DEPTH_LIMIT", "reusable workflow call depth exceeds 10 levels")
			continue
		}

		requested := githubJobPermissions(bom.Assets[caller], edge.call.Job)
		effectivePermissions := requested
		permissionResolution := "caller-job-ceiling"
		if caller != root {
			effectivePermissions = constrainGitHubPermissions(requested, inheritedPermissions)
			permissionResolution = "nested-bounded-intersection"
		}
		effectiveSecrets := effectiveReusableSecrets(availableSecrets, edge.call.SecretMode)
		pathIDs := make([]string, 0, len(stack)+1)
		for _, index := range stack {
			pathIDs = append(pathIDs, bom.Assets[index].ID)
		}
		pathIDs = append(pathIDs, bom.Assets[edge.callee].ID)
		*hops = append(*hops, model.GitHubReusableWorkflowHop{
			Depth: depth, CallerID: bom.Assets[caller].ID, CalleeID: bom.Assets[edge.callee].ID,
			Job: edge.call.Job, Path: pathIDs, PermissionSource: edge.call.PermissionSource,
			PermissionResolution: permissionResolution, EffectivePermissions: effectivePermissions,
			SecretMode: edge.call.SecretMode, EffectiveSecretMode: effectiveSecrets,
			SecretNames: append([]string(nil), edge.call.SecretNames...), EvidenceIDs: append([]string(nil), edge.call.EvidenceIDs...),
		})

		if stackContains(stack, edge.callee) {
			addReusableDiagnostic(diagnostics, bom.Assets[root], "GITHUB_REUSABLE_WORKFLOW_CYCLE", "reusable workflow cycle detected: "+strings.Join(pathIDs, " -> "))
			continue
		}
		nextStack := append(append([]int(nil), stack...), edge.callee)
		walkReusableWorkflows(bom, edges, root, edge.callee, effectivePermissions, effectiveSecrets, nextStack, hops, diagnostics)
	}
}

func githubJobPermissions(asset model.Asset, job string) []model.Capability {
	var result []model.Capability
	for _, capability := range asset.Capabilities {
		if capability.Scope == nil || capability.Scope.Kind != "github-actions-job" || len(capability.Scope.Values) == 0 || capability.Scope.Values[0] != job {
			continue
		}
		if capability.Resource != "github:repository" && capability.Resource != "github:oidc-token" {
			continue
		}
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Action != result[j].Action {
			return result[i].Action < result[j].Action
		}
		return result[i].Resource < result[j].Resource
	})
	return result
}

func constrainGitHubPermissions(requested, ceiling []model.Capability) []model.Capability {
	var result []model.Capability
	for _, capability := range requested {
		for _, limit := range ceiling {
			if !githubPermissionCovers(limit, capability) {
				continue
			}
			bounded := capability
			if normalize.EffectRank(limit.Effect) < normalize.EffectRank(bounded.Effect) {
				bounded.Effect = limit.Effect
			}
			bounded.EvidenceIDs = appendUniqueStrings(bounded.EvidenceIDs, limit.EvidenceIDs...)
			result = append(result, bounded)
			break
		}
	}
	return result
}

func githubPermissionCovers(limit, requested model.Capability) bool {
	if limit.Resource != requested.Resource {
		return false
	}
	return limit.Action == requested.Action || (limit.Action == "github.repository.*" && requested.Resource == "github:repository")
}

func effectiveReusableSecrets(available, mode string) string {
	switch mode {
	case "inherit":
		if available == "none" {
			return "none"
		}
		return "inherited"
	case "explicit":
		return "explicit"
	default:
		return "none"
	}
}

func reusableWorkflowPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimPrefix(value, "$/")
	return strings.TrimPrefix(path.Clean("/"+value), "/")
}

func stackContains(stack []int, target int) bool {
	for _, value := range stack {
		if value == target {
			return true
		}
	}
	return false
}

func addReusableDiagnostic(diagnostics map[string]model.Diagnostic, asset model.Asset, code, message string) {
	key := code + "\x00" + asset.Source.Path + "\x00" + message
	diagnostics[key] = model.Diagnostic{Severity: "warning", Code: code, Path: asset.Source.Path, Parser: "github-actions-effective", Message: message}
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	result := make([]string, 0, len(values)+len(additions))
	for _, value := range append(append([]string(nil), values...), additions...) {
		if _, exists := seen[value]; value == "" || exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
