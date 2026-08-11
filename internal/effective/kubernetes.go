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
			if signals := rbacEscalationSignals(asset.Capabilities); len(signals) > 0 {
				asset.Controls = append(asset.Controls, model.Control{Type: "rbacPrivilegeEscalation", Value: map[string]any{"signals": signals}})
				bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(asset, "KUBERNETES_RBAC_PRIVILEGE_ESCALATION", "role grants privilege-escalation capabilities: "+strings.Join(signals, ", ")))
			}
		case "identity":
			identities[asset.Name] = asset
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
			applyEffectiveServiceAccountToken(workload, identity)
			for _, grant := range grants[identity.Name] {
				applyGrant(workload, grant)
				appendGrantPaths(paths, workload.ID, identity.ID, grant)
			}
		}
	}
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
	maxEffect, maxRank, wildcard := "unknown", 0, false
	for _, capability := range inherited {
		actions = append(actions, capability.Action)
		if rank := kubernetesEffectRank(capability.Effect); rank > maxRank {
			maxEffect, maxRank = capability.Effect, rank
		}
		if strings.Contains(capability.Action, "*") || strings.Contains(capability.Resource, "*") {
			wildcard = true
		}
	}
	actions = uniqueSorted(actions)
	signals := rbacEscalationSignals(inherited)
	asset.Controls = append(asset.Controls, model.Control{Type: "declaredVsEffectiveAccess", Value: map[string]any{
		"declaredCapabilityCount": len(declaredSet), "effectiveCapabilityCount": len(effectiveSet),
		"inheritedCapabilityCount": len(inherited), "inheritedActions": actions, "maxInheritedEffect": maxEffect,
		"wildcard": wildcard, "privilegeEscalationSignals": signals, "sources": sources,
	}})
	if maxRank >= kubernetesEffectRank("admin") || wildcard || len(signals) > 0 {
		message := fmt.Sprintf("effective access adds %d inherited capabilities; maximum effect is %s", len(inherited), maxEffect)
		if len(signals) > 0 {
			message += "; escalation signals: " + strings.Join(signals, ", ")
		}
		bom.Diagnostics = append(bom.Diagnostics, kubernetesDiagnostic(asset, "KUBERNETES_EFFECTIVE_ACCESS_EXPANSION", message))
	}
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

func applyEffectiveServiceAccountToken(workload, identity *model.Asset) {
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
		resource := strings.ToLower(capability.Resource)
		switch {
		case strings.HasSuffix(action, ".bind"):
			found["bind"] = struct{}{}
		case strings.HasSuffix(action, ".escalate"):
			found["escalate"] = struct{}{}
		case strings.HasSuffix(action, ".impersonate"):
			found["impersonate"] = struct{}{}
		}
		if strings.Contains(action, "*") || strings.Contains(resource, "*") {
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
