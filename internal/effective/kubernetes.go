package effective

import (
	"sort"

	"github.com/opscustodian/opscustodian/internal/model"
)

type effectiveGrant struct {
	Role, Binding string
	Capabilities  []model.Capability
	Evidence      []model.Evidence
}

func ComposeKubernetesRBAC(bom *model.AgentBOM) {
	roles, identities := map[string]*model.Asset{}, map[string]*model.Asset{}
	for index := range bom.Assets {
		asset := &bom.Assets[index]
		switch asset.Type {
		case "authorization-role":
			roles[asset.Name] = asset
		case "identity":
			identities[asset.Name] = asset
		}
	}
	grants := map[string][]effectiveGrant{}
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
			grant := buildGrant(role, binding)
			applyGrant(identity, grant)
			grants[identity.Name] = append(grants[identity.Name], grant)
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
			for _, grant := range grants[identity.Name] {
				applyGrant(workload, grant)
			}
		}
	}
	sort.Slice(bom.Diagnostics, func(i, j int) bool {
		return bom.Diagnostics[i].Path+bom.Diagnostics[i].Code+bom.Diagnostics[i].Message < bom.Diagnostics[j].Path+bom.Diagnostics[j].Code+bom.Diagnostics[j].Message
	})
}

func buildGrant(role, binding *model.Asset) effectiveGrant {
	evidence := append([]model.Evidence(nil), role.Evidence...)
	evidence = append(evidence, binding.Evidence...)
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	capabilities := make([]model.Capability, 0, len(role.Capabilities))
	for _, capability := range role.Capabilities {
		capability.EvidenceIDs = append([]string(nil), evidenceIDs...)
		capabilities = append(capabilities, capability)
	}
	return effectiveGrant{Role: role.Name, Binding: binding.Name, Capabilities: capabilities, Evidence: evidence}
}

func applyGrant(asset *model.Asset, grant effectiveGrant) {
	asset.Capabilities = append(asset.Capabilities, grant.Capabilities...)
	copyUniqueEvidence(asset, grant.Evidence)
	asset.Controls = append(asset.Controls, model.Control{Type: "effectiveRBACGrant", Value: map[string]string{"role": grant.Role, "binding": grant.Binding}})
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
