package effective

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

type effectiveGrant struct {
	Role, RoleID, Binding, BindingID string
	Capabilities                     []model.Capability
	Evidence                         []model.Evidence
}

func ComposeKubernetesRBAC(bom *model.AgentBOM) {
	roles, identities := map[string]*model.Asset{}, map[string]*model.Asset{}
	declared := map[string][]model.Capability{}
	for index := range bom.Assets {
		asset := &bom.Assets[index]
		if asset.Type == "identity" || asset.Type == "workload" {
			declared[asset.ID] = append([]model.Capability(nil), asset.Capabilities...)
		}
		switch asset.Type {
		case "authorization-role":
			roles[asset.Name] = asset
		case "identity":
			identities[asset.Name] = asset
		}
	}
	composeAggregatedClusterRoles(bom, roles)
	for _, role := range roles {
		if signals := rbacEscalationSignals(role.Capabilities); len(signals) > 0 {
			role.Controls = append(role.Controls, model.Control{Type: "rbacPrivilegeEscalation", Value: map[string]any{"signals": signals}})
			bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(role, "KUBERNETES_RBAC_PRIVILEGE_ESCALATION", "role grants privilege-escalation capabilities: "+strings.Join(signals, ", ")))
			appendFinding(bom, model.Finding{
				Type: "kubernetes-rbac-privilege-escalation", Severity: "critical", AssetID: role.ID,
				Title:         "Kubernetes role can escalate privileges",
				Reason:        "Role grants privilege-escalation capabilities: " + strings.Join(signals, ", "),
				RemediationID: "kubernetes.reduce-rbac-privileges",
				Remediation:   "Remove wildcard, bind, escalate, impersonate, or equivalent privilege-management permissions from the role.",
				Evidence:      assetFindingEvidence(role, "kubernetes"), Attributes: map[string]any{"signals": signals},
			})
		}
	}
	grants := map[string][]effectiveGrant{}
	paths := map[string]model.AccessPath{}
	for _, path := range bom.AccessPaths {
		paths[path.ID] = path
	}
	for index := range bom.Assets {
		binding := &bom.Assets[index]
		if binding.Type != "authorization-binding" {
			continue
		}
		roleName := referenceOfType(binding.Dependencies, "authorization-role")
		role := roles[roleName]
		if role == nil {
			bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(binding, "KUBERNETES_RBAC_ROLE_UNRESOLVED", "binding references an undiscovered role: "+roleName))
			continue
		}
		for _, subject := range binding.Identities {
			identity := identities[subject.Reference]
			if identity == nil {
				bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(binding, "KUBERNETES_RBAC_SUBJECT_UNRESOLVED", "binding references an undiscovered ServiceAccount: "+subject.Reference))
				continue
			}
			grant, ignoredNonResourceURLs := buildGrant(role, binding)
			if ignoredNonResourceURLs > 0 {
				bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(binding, "KUBERNETES_RBAC_NON_RESOURCE_URL_NAMESPACED", fmt.Sprintf("namespaced binding cannot grant %d non-resource URL capabilities", ignoredNonResourceURLs)))
			}
			if len(grant.Capabilities) == 0 {
				continue
			}
			applyGrant(identity, grant)
			grants[identity.Name] = append(grants[identity.Name], grant)
			appendGrantPaths(paths, identity.ID, "", grant)
		}
	}
	for index := range bom.Assets {
		workload := &bom.Assets[index]
		if workload.Type != "workload" {
			continue
		}
		for _, identityReference := range workload.Identities {
			identity := identities[identityReference.Reference]
			if identity == nil {
				bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(workload, "KUBERNETES_SERVICE_ACCOUNT_UNRESOLVED", "workload references an undiscovered ServiceAccount: "+identityReference.Reference))
				continue
			}
			applyEffectiveServiceAccountToken(bom, workload, identity)
			for _, grant := range grants[identity.Name] {
				applyGrant(workload, grant)
				appendGrantPaths(paths, workload.ID, identity.ID, grant)
			}
		}
	}
	applyProjectedTokenFindings(bom)
	bom.AccessPaths = make([]model.AccessPath, 0, len(paths))
	for _, path := range paths {
		bom.AccessPaths = append(bom.AccessPaths, path)
	}
	sort.Slice(bom.AccessPaths, func(i, j int) bool { return bom.AccessPaths[i].ID < bom.AccessPaths[j].ID })
	for index := range bom.Assets {
		asset := &bom.Assets[index]
		baseline, exists := declared[asset.ID]
		if exists {
			applyDeclaredEffectiveAccess(bom, asset, baseline)
		}
	}
	sort.Slice(bom.Diagnostics, func(i, j int) bool {
		return bom.Diagnostics[i].Path+bom.Diagnostics[i].Code+bom.Diagnostics[i].Message < bom.Diagnostics[j].Path+bom.Diagnostics[j].Code+bom.Diagnostics[j].Message
	})
}

func composeAggregatedClusterRoles(bom *model.AgentBOM, roles map[string]*model.Asset) {
	matchedByRole := map[string][]*model.Asset{}
	for _, aggregate := range roles {
		selectors := aggregationRuleOf(aggregate.Controls)
		if len(selectors) == 0 {
			continue
		}
		for _, candidate := range roles {
			if candidate.ID == aggregate.ID || !strings.HasPrefix(candidate.Name, "cluster/") {
				continue
			}
			labels := kubernetesLabelsOf(candidate.Controls)
			if matchesAnySelector(labels, selectors) {
				matchedByRole[aggregate.Name] = append(matchedByRole[aggregate.Name], candidate)
			}
		}
		if len(matchedByRole[aggregate.Name]) == 0 {
			bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(aggregate, "KUBERNETES_AGGREGATION_SELECTOR_UNMATCHED", "ClusterRole aggregation selectors matched no discovered ClusterRoles"))
		}
	}
	for aggregateName := range matchedByRole {
		sort.Slice(matchedByRole[aggregateName], func(i, j int) bool {
			return matchedByRole[aggregateName][i].ID < matchedByRole[aggregateName][j].ID
		})
	}
	reportAggregationCycles(bom, roles, matchedByRole)
	for iteration := 0; iteration < len(roles); iteration++ {
		changed := false
		for aggregateName, matched := range matchedByRole {
			aggregate := roles[aggregateName]
			for _, source := range matched {
				copyUniqueEvidence(aggregate, source.Evidence)
				for _, capability := range source.Capabilities {
					capability = rebaseAggregatedCapability(capability, source.Name, aggregate.Name)
					if mergeCapability(aggregate, capability) {
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	for aggregateName, matched := range matchedByRole {
		names := make([]string, 0, len(matched))
		for _, role := range matched {
			names = append(names, role.Name)
		}
		sort.Strings(names)
		roles[aggregateName].Controls = append(roles[aggregateName].Controls, model.Control{Type: "effectiveClusterRoleAggregation", Value: map[string]any{"matchedRoles": names}})
	}
}

const maxAggregationCycles = 100

func reportAggregationCycles(bom *model.AgentBOM, roles map[string]*model.Asset, graph map[string][]*model.Asset) {
	nodes := make([]string, 0, len(graph))
	for node := range graph {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	cycles := map[string][]string{}
	for _, start := range nodes {
		visited := map[string]bool{start: true}
		findAggregationCycles(start, start, graph, visited, []string{start}, cycles)
		if len(cycles) > maxAggregationCycles {
			break
		}
	}
	keys := make([]string, 0, len(cycles))
	for key := range cycles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > maxAggregationCycles {
		keys = keys[:maxAggregationCycles]
	}
	for _, key := range keys {
		cycle := cycles[key]
		role := roles[cycle[0]]
		closed := append(append([]string(nil), cycle...), cycle[0])
		role.Controls = append(role.Controls, model.Control{Type: "kubernetesAggregationCycle", Value: map[string]any{"roles": closed}})
		bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(role, "KUBERNETES_AGGREGATION_CYCLE", "aggregated ClusterRole cycle detected: "+strings.Join(closed, " -> ")))
	}
	if len(cycles) > maxAggregationCycles && len(nodes) > 0 {
		bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(roles[nodes[0]], "KUBERNETES_AGGREGATION_CYCLE_LIMIT", fmt.Sprintf("aggregation cycle reporting stopped at the safety limit of %d cycles", maxAggregationCycles)))
	}
}

func findAggregationCycles(start, current string, graph map[string][]*model.Asset, visited map[string]bool, path []string, cycles map[string][]string) {
	if len(cycles) > maxAggregationCycles {
		return
	}
	for _, candidate := range graph[current] {
		next := candidate.Name
		if _, isAggregate := graph[next]; !isAggregate {
			continue
		}
		if next == start && len(path) > 1 {
			canonical := canonicalAggregationCycle(path)
			cycles[strings.Join(canonical, "\x00")] = canonical
			continue
		}
		if visited[next] || len(path) >= len(graph) {
			continue
		}
		visited[next] = true
		findAggregationCycles(start, next, graph, visited, append(path, next), cycles)
		delete(visited, next)
	}
}

func canonicalAggregationCycle(cycle []string) []string {
	best := append([]string(nil), cycle...)
	bestKey := strings.Join(best, "\x00")
	for index := 1; index < len(cycle); index++ {
		rotated := append(append([]string(nil), cycle[index:]...), cycle[:index]...)
		if key := strings.Join(rotated, "\x00"); key < bestKey {
			best, bestKey = rotated, key
		}
	}
	return best
}

func rebaseAggregatedCapability(capability model.Capability, sourceRole, aggregateRole string) model.Capability {
	if strings.HasPrefix(capability.Action, "kubernetes.non_resource_url.") {
		return capability
	}
	sourcePrefix := "kubernetes:" + sourceRole + "/"
	if strings.HasPrefix(capability.Resource, sourcePrefix) {
		capability.Resource = "kubernetes:" + aggregateRole + "/" + strings.TrimPrefix(capability.Resource, sourcePrefix)
		capability.Scope = nil
	}
	return capability
}

func mergeCapability(asset *model.Asset, candidate model.Capability) bool {
	key := capabilityIdentity(candidate)
	for index := range asset.Capabilities {
		if capabilityIdentity(asset.Capabilities[index]) != key {
			continue
		}
		asset.Capabilities[index].EvidenceIDs = uniqueSorted(append(asset.Capabilities[index].EvidenceIDs, candidate.EvidenceIDs...))
		return false
	}
	asset.Capabilities = append(asset.Capabilities, candidate)
	return true
}

func aggregationRuleOf(controls []model.Control) []map[string]any {
	for _, control := range controls {
		if control.Type == "kubernetesAggregationRule" {
			if value, ok := control.Value.([]map[string]any); ok {
				return value
			}
		}
	}
	return nil
}

func kubernetesLabelsOf(controls []model.Control) map[string]string {
	for _, control := range controls {
		if control.Type == "kubernetesLabels" {
			if value, ok := control.Value.(map[string]string); ok {
				return value
			}
		}
	}
	return nil
}

func matchesAnySelector(labels map[string]string, selectors []map[string]any) bool {
	for _, selector := range selectors {
		if matchesSelector(labels, selector) {
			return true
		}
	}
	return false
}

func matchesSelector(labels map[string]string, selector map[string]any) bool {
	if required, ok := selector["matchLabels"].(map[string]string); ok {
		for key, value := range required {
			if labels[key] != value {
				return false
			}
		}
	}
	if expressions, ok := selector["matchExpressions"].([]map[string]any); ok {
		for _, expression := range expressions {
			key, _ := expression["key"].(string)
			operator, _ := expression["operator"].(string)
			values, _ := expression["values"].([]string)
			labelValue, exists := labels[key]
			contains := false
			for _, value := range values {
				contains = contains || value == labelValue
			}
			switch operator {
			case "In":
				if !exists || !contains {
					return false
				}
			case "NotIn":
				if exists && contains {
					return false
				}
			case "Exists":
				if !exists {
					return false
				}
			case "DoesNotExist":
				if exists {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func appendGrantPaths(paths map[string]model.AccessPath, origin, principal string, grant effectiveGrant) {
	for _, capability := range grant.Capabilities {
		steps := []model.AccessPathStep{{Kind: "origin", AssetID: origin}}
		if principal != "" && principal != origin {
			steps = append(steps, model.AccessPathStep{Kind: "principal", AssetID: principal})
		}
		steps = append(steps,
			model.AccessPathStep{Kind: "grant", AssetID: grant.BindingID},
			model.AccessPathStep{Kind: "entitlement", AssetID: grant.RoleID},
		)
		identity := origin + "\x00" + grant.BindingID + "\x00" + grant.RoleID + "\x00" + capabilityIdentity(capability)
		sum := sha256.Sum256([]byte(identity))
		path := model.AccessPath{
			ID: fmt.Sprintf("access-path-%x", sum[:8]), Origin: origin, Steps: steps,
			Capability: capability, Confidence: "high", EvidenceIDs: append([]string(nil), capability.EvidenceIDs...),
		}
		paths[path.ID] = path
	}
}

func applyDeclaredEffectiveAccess(bom *model.AgentBOM, asset *model.Asset, declared []model.Capability) {
	declaredSet := uniqueCapabilitySet(declared)
	effectiveSet := uniqueCapabilitySet(asset.Capabilities)
	var inherited []model.Capability
	for key, capability := range effectiveSet {
		if _, exists := declaredSet[key]; !exists {
			inherited = append(inherited, capability)
		}
	}
	if len(inherited) == 0 {
		return
	}
	sort.Slice(inherited, func(i, j int) bool { return capabilityIdentity(inherited[i]) < capabilityIdentity(inherited[j]) })
	actions, sources := make([]string, 0, len(inherited)), effectiveAccessSources(asset.Controls)
	maxEffect, maxRank, wildcard, privilegedWildcard := "unknown", 0, false, false
	for _, capability := range inherited {
		actions = append(actions, capability.Action)
		if rank := kubernetesEffectRank(capability.Effect); rank > maxRank {
			maxEffect, maxRank = capability.Effect, rank
		}
		if strings.Contains(capability.Action, "*") || strings.Contains(capability.Resource, "*") {
			wildcard = true
		}
		privilegedWildcard = privilegedRBACWildcard(capability) || privilegedWildcard
	}
	actions = uniqueSorted(actions)
	signals := rbacEscalationSignals(inherited)
	asset.Controls = append(asset.Controls, model.Control{Type: "declaredVsEffectiveAccess", Value: map[string]any{
		"declaredCapabilityCount": len(declaredSet), "effectiveCapabilityCount": len(effectiveSet),
		"inheritedCapabilityCount": len(inherited), "inheritedActions": actions, "maxInheritedEffect": maxEffect,
		"wildcard": wildcard, "privilegeEscalationSignals": signals, "sources": sources,
	}})
	if maxRank >= kubernetesEffectRank("admin") || privilegedWildcard || len(signals) > 0 {
		message := fmt.Sprintf("effective access adds %d inherited capabilities; maximum effect is %s", len(inherited), maxEffect)
		if len(signals) > 0 {
			message += "; escalation signals: " + strings.Join(signals, ", ")
		}
		bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(asset, "KUBERNETES_EFFECTIVE_ACCESS_EXPANSION", message))
		severity := "high"
		if maxRank >= kubernetesEffectRank("admin") || len(signals) > 0 {
			severity = "critical"
		}
		identity := asset.ID + "\x00kubernetes-effective-access-expansion\x00" + strings.Join(actions, "\x00") + "\x00" + strings.Join(sources, "\x00")
		sum := sha256.Sum256([]byte(identity))
		bom.Findings = append(bom.Findings, model.Finding{
			ID: fmt.Sprintf("finding-%x", sum[:8]), Type: "kubernetes-effective-access-expansion",
			Severity: severity, AssetID: asset.ID, Title: "Declared access is narrower than effective Kubernetes access",
			Reason: message, RemediationID: "kubernetes.reduce-effective-access", Remediation: "Reduce the bound RBAC role, narrow the binding subject or scope, and disable unnecessary token exposure.",
			Evidence: findingEvidence(bom, asset.ID, inherited), Attributes: map[string]any{
				"declaredCapabilityCount": len(declaredSet), "effectiveCapabilityCount": len(effectiveSet),
				"inheritedCapabilityCount": len(inherited), "inheritedActions": actions,
				"maxInheritedEffect": maxEffect, "wildcard": wildcard,
				"privilegeEscalationSignals": signals, "sources": sources,
			},
		})
	}
}

func findingEvidence(bom *model.AgentBOM, origin string, capabilities []model.Capability) []model.FindingEvidence {
	wanted := map[string]struct{}{}
	wantedCapabilities := map[string]struct{}{}
	for _, capability := range capabilities {
		wantedCapabilities[capabilityIdentity(capability)] = struct{}{}
		for _, evidenceID := range capability.EvidenceIDs {
			wanted[evidenceID] = struct{}{}
		}
	}
	relevantAssets := map[string]struct{}{origin: {}}
	for _, path := range bom.AccessPaths {
		if path.Origin != origin {
			continue
		}
		if _, exists := wantedCapabilities[capabilityIdentity(path.Capability)]; !exists {
			continue
		}
		for _, step := range path.Steps {
			relevantAssets[step.AssetID] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	var result []model.FindingEvidence
	for _, asset := range bom.Assets {
		if _, relevant := relevantAssets[asset.ID]; !relevant {
			continue
		}
		// Effective capabilities may copy evidence onto the origin during graph
		// composition. Prefer the original Kubernetes grant assets so findings
		// remain concise and do not duplicate ownership/correlation evidence.
		if asset.ID == origin || (asset.Type != "authorization-role" && asset.Type != "authorization-binding") {
			continue
		}
		for _, evidence := range asset.Evidence {
			if evidence.Parser != "kubernetes" {
				continue
			}
			if _, exists := wanted[evidence.ID]; !exists {
				continue
			}
			key := asset.ID + "\x00" + evidence.ID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, model.FindingEvidence{AssetID: asset.ID, EvidenceID: evidence.ID})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AssetID+"\x00"+result[i].EvidenceID < result[j].AssetID+"\x00"+result[j].EvidenceID
	})
	return result
}

func uniqueCapabilitySet(capabilities []model.Capability) map[string]model.Capability {
	result := map[string]model.Capability{}
	for _, capability := range capabilities {
		result[capabilityIdentity(capability)] = capability
	}
	return result
}

func capabilityIdentity(capability model.Capability) string {
	return strings.ToLower(strings.Join([]string{capability.Action, capability.Resource, capability.Effect, capability.Environment}, "\x00"))
}

func effectiveAccessSources(controls []model.Control) []string {
	var result []string
	for _, control := range controls {
		switch control.Type {
		case "effectiveRBACGrant":
			if value, ok := control.Value.(map[string]string); ok {
				result = append(result, "rbac:"+value["role"]+"@"+value["binding"])
			}
		case "effectiveServiceAccountToken":
			if value, ok := control.Value.(map[string]any); ok {
				if enabled, _ := value["enabled"].(bool); enabled {
					source, _ := value["source"].(string)
					result = append(result, "service-account-token:"+source)
				}
			}
		}
	}
	return uniqueSorted(result)
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func kubernetesEffectRank(effect string) int {
	switch strings.ToLower(effect) {
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

func applyEffectiveServiceAccountToken(bom *model.AgentBOM, workload, identity *model.Asset) {
	enabled, source := true, "kubernetes-default"
	if value, exists := booleanControl(identity.Controls, "automountServiceAccountToken"); exists {
		enabled, source = value, "service-account"
	}
	if value, exists := booleanControl(workload.Controls, "automountServiceAccountToken"); exists {
		enabled, source = value, "workload"
	}
	workload.Controls = append(workload.Controls, model.Control{Type: "effectiveServiceAccountToken", Value: map[string]any{"enabled": enabled, "source": source}})
	if !enabled {
		return
	}
	evidence := []model.Evidence{}
	if item, exists := kubernetesEvidence(workload); exists {
		evidence = append(evidence, item)
	}
	if source == "service-account" {
		if item, exists := kubernetesEvidence(identity); exists {
			evidence = append(evidence, item)
		}
	}
	copyUniqueEvidence(workload, evidence)
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	workload.Capabilities = append(workload.Capabilities, model.Capability{
		Action: "kubernetes.service_account_token.use", Resource: "kubernetes:service-account/" + identity.Name,
		Effect: "execute", Environment: namespaceOf(identity.Name), EvidenceIDs: evidenceIDs,
	})
	severity := "medium"
	reason := "workload can use an automatically mounted ServiceAccount token"
	if source == "kubernetes-default" {
		severity = "high"
		reason += " because neither workload nor ServiceAccount disables the Kubernetes default"
	}
	appendFinding(bom, model.Finding{
		Type: "kubernetes-service-account-token-exposure", Severity: severity, AssetID: workload.ID,
		Title: "Workload receives a ServiceAccount token", Reason: reason,
		RemediationID: "kubernetes.disable-token-automount",
		Remediation:   "Set automountServiceAccountToken to false unless the workload requires Kubernetes API access.",
		Evidence:      assetFindingEvidence(workload, "kubernetes"), Attributes: map[string]any{
			"serviceAccount": identity.Name, "source": source, "enabled": true,
		},
	})
}

func applyProjectedTokenFindings(bom *model.AgentBOM) {
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		if asset.Type != "workload" {
			continue
		}
		for _, control := range asset.Controls {
			if control.Type != "serviceAccountTokenProjection" {
				continue
			}
			projection, ok := control.Value.(map[string]any)
			if !ok {
				continue
			}
			mountedBy, _ := projection["mountedBy"].([]string)
			if len(mountedBy) == 0 {
				continue
			}
			audience, _ := projection["audience"].(string)
			expiration, _ := projection["expirationSeconds"].(int)
			var signals []string
			severity := "medium"
			if audience == "" || audience == "kubernetes-default" {
				signals = append(signals, "default-audience")
			}
			if expiration > 3600 {
				signals = append(signals, "long-lived")
				severity = "high"
			}
			if len(signals) == 0 {
				continue
			}
			sort.Strings(signals)
			appendFinding(bom, model.Finding{
				Type: "kubernetes-projected-token-risk", Severity: severity, AssetID: asset.ID,
				Title:         "Projected ServiceAccount token has risky settings",
				Reason:        "Mounted projected token has risk signals: " + strings.Join(signals, ", "),
				RemediationID: "kubernetes.harden-projected-token",
				Remediation:   "Use a workload-specific audience and an expiration of at most 3600 seconds.",
				Evidence:      assetFindingEvidence(asset, "kubernetes"), Attributes: map[string]any{
					"audience": audience, "expirationSeconds": expiration, "mountedBy": mountedBy, "signals": signals,
				},
			})
		}
	}
}

func appendFinding(bom *model.AgentBOM, finding model.Finding) {
	identity := finding.Type + "\x00" + finding.AssetID
	if signals, ok := finding.Attributes["signals"].([]string); ok {
		identity += "\x00" + strings.Join(signals, "\x00")
	}
	sum := sha256.Sum256([]byte(identity))
	finding.ID = fmt.Sprintf("finding-%x", sum[:8])
	for _, existing := range bom.Findings {
		if existing.ID == finding.ID {
			return
		}
	}
	bom.Findings = append(bom.Findings, finding)
}

func assetFindingEvidence(asset *model.Asset, parser string) []model.FindingEvidence {
	result := make([]model.FindingEvidence, 0, len(asset.Evidence))
	for _, evidence := range asset.Evidence {
		if evidence.Parser == parser {
			result = append(result, model.FindingEvidence{AssetID: asset.ID, EvidenceID: evidence.ID})
		}
	}
	return result
}

func booleanControl(controls []model.Control, controlType string) (bool, bool) {
	for _, control := range controls {
		if control.Type != controlType {
			continue
		}
		value, ok := control.Value.(bool)
		return value, ok
	}
	return false, false
}

func kubernetesEvidence(asset *model.Asset) (model.Evidence, bool) {
	for _, evidence := range asset.Evidence {
		if evidence.Parser == "kubernetes" {
			return evidence, true
		}
	}
	return model.Evidence{}, false
}

func namespaceOf(qualified string) string {
	for index, value := range qualified {
		if value == '/' {
			return qualified[:index]
		}
	}
	return "default"
}

func buildGrant(role, binding *model.Asset) (effectiveGrant, int) {
	evidence := append([]model.Evidence(nil), role.Evidence...)
	evidence = append(evidence, binding.Evidence...)
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	capabilities := make([]model.Capability, 0, len(role.Capabilities))
	ignoredNonResourceURLs := 0
	for _, capability := range role.Capabilities {
		if strings.HasPrefix(capability.Action, "kubernetes.non_resource_url.") && !strings.HasPrefix(binding.Name, "cluster/") {
			ignoredNonResourceURLs++
			continue
		}
		capability.EvidenceIDs = append([]string(nil), evidenceIDs...)
		capability.Resource, capability.Environment = effectiveKubernetesResource(capability.Resource, role.Name, binding.Name)
		// The declared role scope no longer describes the binding-specialized
		// resource. Let the final normalization pass infer the effective scope.
		capability.Scope = nil
		capabilities = append(capabilities, capability)
	}
	return effectiveGrant{Role: role.Name, RoleID: role.ID, Binding: binding.Name, BindingID: binding.ID, Capabilities: capabilities, Evidence: evidence}, ignoredNonResourceURLs
}

func effectiveKubernetesResource(resource, roleName, bindingName string) (string, string) {
	if strings.Contains(resource, "/non-resource-url") {
		return resource, "cluster"
	}
	prefix := "kubernetes:" + roleName + "/"
	suffix := strings.TrimPrefix(resource, prefix)
	if strings.HasPrefix(bindingName, "cluster/") {
		return "kubernetes:cluster/" + suffix, "cluster"
	}
	namespace := namespaceOf(bindingName)
	return "kubernetes:" + namespace + "/" + suffix, namespace
}

func applyGrant(asset *model.Asset, grant effectiveGrant) {
	asset.Capabilities = append(asset.Capabilities, grant.Capabilities...)
	copyUniqueEvidence(asset, grant.Evidence)
	asset.Controls = append(asset.Controls, model.Control{Type: "effectiveRBACGrant", Value: map[string]string{"role": grant.Role, "binding": grant.Binding}})
	if signals := rbacEscalationSignals(grant.Capabilities); len(signals) > 0 {
		asset.Controls = append(asset.Controls, model.Control{Type: "effectiveRBACPrivilegeEscalation", Value: map[string]any{
			"role": grant.Role, "binding": grant.Binding, "signals": signals,
		}})
	}
}

func rbacEscalationSignals(capabilities []model.Capability) []string {
	found := map[string]struct{}{}
	for _, capability := range capabilities {
		action := strings.ToLower(capability.Action)
		switch {
		case strings.HasSuffix(action, ".bind"):
			found["bind"] = struct{}{}
		case strings.HasSuffix(action, ".escalate"):
			found["escalate"] = struct{}{}
		case strings.HasSuffix(action, ".impersonate"):
			found["impersonate"] = struct{}{}
		}
		if privilegedRBACWildcard(capability) {
			found["wildcard"] = struct{}{}
		}
	}
	result := make([]string, 0, len(found))
	for signal := range found {
		result = append(result, signal)
	}
	sort.Strings(result)
	return result
}

func privilegedRBACWildcard(capability model.Capability) bool {
	action, resource := strings.ToLower(capability.Action), strings.ToLower(capability.Resource)
	if strings.Contains(action, "*") {
		return true
	}
	if strings.HasPrefix(action, "kubernetes.non_resource_url.") {
		return strings.Contains(resource, "*")
	}
	// The final RBAC resource segment is an object name. Its default `*`
	// means all objects of an otherwise specific resource kind; keep it as
	// broad scope, but do not classify it as privilege escalation.
	return strings.Contains(strings.TrimSuffix(resource, "/*"), "*")
}

func copyUniqueEvidence(asset *model.Asset, evidence []model.Evidence) {
	existing := map[string]struct{}{}
	for _, item := range asset.Evidence {
		existing[item.ID] = struct{}{}
	}
	for _, item := range evidence {
		if _, exists := existing[item.ID]; exists {
			continue
		}
		asset.Evidence = append(asset.Evidence, item)
		existing[item.ID] = struct{}{}
	}
}

func referenceOfType(values []model.Reference, referenceType string) string {
	for _, value := range values {
		if value.Type == referenceType {
			return value.Reference
		}
	}
	return ""
}

func kubernetesDiagnostic(asset *model.Asset, code, message string) model.Diagnostic {
	return model.Diagnostic{Severity: "warning", Code: code, Path: asset.Source.Path, Parser: "kubernetes-effective-access", Message: message}
}
