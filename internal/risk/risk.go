package risk

import (
	"regexp"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

var productionToken = regexp.MustCompile(`(?i)(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)`)

type Assessment struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Factors []Factor `json:"factors"`
}

type Factor struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

func Capability(asset model.Asset, capability model.Capability) Assessment {
	assessment := Assessment{}
	effectScores := map[string]int{"observe": 5, "read": 10, "execute": 25, "write": 40, "delete": 60, "admin": 65, "unknown": 25}
	add(&assessment, "effect", effectScores[capability.Effect], "capability effect is "+capability.Effect)
	if strings.EqualFold(capability.Environment, "production") || containsProduction(capability.Resource) {
		add(&assessment, "production", 20, "capability targets a production context")
	} else if strings.EqualFold(capability.Environment, "staging") {
		add(&assessment, "staging", 8, "capability targets staging")
	}
	if strings.Contains(capability.Resource, "*") || strings.HasSuffix(capability.Action, ".*") {
		add(&assessment, "broad-scope", 15, "capability contains a wildcard scope")
	}
	if len(asset.Credentials) > 0 {
		add(&assessment, "credentialed", 8, "asset uses one or more credential references")
	}
	if hasControl(asset, "humanApproval") {
		add(&assessment, "human-approval", -15, "human approval limits execution")
	}
	if strings.HasPrefix(capability.Action, "github.safe_output.") && hasControl(asset, "safeOutputs") {
		add(&assessment, "safe-output", -15, "write is gated through a declared safe output")
	}
	addConfidence(&assessment, asset, capability.EvidenceIDs)
	return finalize(assessment)
}

func CapabilityEscalation(asset model.Asset, capability model.Capability, effectExpanded, scopeExpanded bool) Assessment {
	assessment := Capability(asset, capability)
	if effectExpanded {
		add(&assessment, "effect-escalation", 15, "capability effect became more powerful")
	}
	if scopeExpanded {
		add(&assessment, "scope-expansion", 20, "capability applies to a broader resource scope")
	}
	return finalize(assessment)
}

func Credential(asset model.Asset, credential model.CredentialReference) Assessment {
	assessment := Assessment{}
	add(&assessment, "credential", 45, "asset gained a credential reference")
	if containsProduction(credential.Reference) {
		add(&assessment, "production-credential", 25, "credential name indicates production access")
	}
	if assetTargetsProduction(asset) {
		add(&assessment, "production", 15, "asset has production capabilities")
	}
	if hasControl(asset, "humanApproval") {
		add(&assessment, "human-approval", -10, "human approval limits credential use")
	}
	return finalize(assessment)
}

func Control(control model.Control, removed bool) Assessment {
	assessment := Assessment{}
	base := 35
	if removed {
		base = 45
	}
	add(&assessment, "control-change", base, "a safety control changed")
	switch control.Type {
	case "humanApproval":
		add(&assessment, "approval-control", 30, "human approval was weakened or removed")
	case "networkPolicy", "networkAllowed", "networkBlocked":
		add(&assessment, "network-control", 15, "network restrictions changed")
	case "safeOutputs":
		add(&assessment, "safe-output-control", 25, "safe output restrictions changed")
	}
	return finalize(assessment)
}

func Relationship(relation model.Relationship, removed bool) Assessment {
	assessment := Assessment{}
	switch relation.Type {
	case "owned-by":
		if removed {
			add(&assessment, "ownership-removed", 65, "asset ownership was removed")
		} else {
			add(&assessment, "ownership-added", 5, "asset ownership was added")
		}
	case "uses-mcp-server":
		add(&assessment, "mcp-access", 40, "asset relationship to an MCP server changed")
	case "uses-tool":
		add(&assessment, "tool-access", 25, "asset tool access changed")
	case "depends-on":
		add(&assessment, "dependency", 25, "agentic dependency changed")
	default:
		add(&assessment, "relationship", 15, "agentic graph relationship changed")
	}
	if relation.TargetType == "asset-reference" {
		add(&assessment, "unresolved-target", 10, "relationship target is not present in the inventory")
	}
	return finalize(assessment)
}

func AssetAdded(asset model.Asset) Assessment {
	assessment := Assessment{}
	add(&assessment, "new-asset", 25, "a new agentic asset was introduced")
	for _, capability := range asset.Capabilities {
		candidate := Capability(asset, capability)
		if candidate.Score > assessment.Score {
			assessment = candidate
			add(&assessment, "new-asset", 10, "risk belongs to a newly introduced asset")
		}
	}
	return finalize(assessment)
}

func add(assessment *Assessment, name string, score int, reason string) {
	if score == 0 {
		return
	}
	assessment.Score += score
	assessment.Factors = append(assessment.Factors, Factor{Name: name, Score: score, Reason: reason})
}

func addConfidence(assessment *Assessment, asset model.Asset, evidenceIDs []string) {
	wanted := map[string]struct{}{}
	for _, id := range evidenceIDs {
		wanted[id] = struct{}{}
	}
	for _, evidence := range asset.Evidence {
		if len(wanted) > 0 {
			if _, exists := wanted[evidence.ID]; !exists {
				continue
			}
		}
		switch evidence.Confidence {
		case "high":
			add(assessment, "high-confidence", 5, "finding is backed by explicit configuration")
		case "low":
			add(assessment, "low-confidence", -5, "finding relies on low-confidence inference")
		}
		return
	}
}

func finalize(assessment Assessment) Assessment {
	if assessment.Score < 0 {
		assessment.Score = 0
	}
	if assessment.Score > 100 {
		assessment.Score = 100
	}
	switch {
	case assessment.Score >= 80:
		assessment.Level = "critical"
	case assessment.Score >= 60:
		assessment.Level = "high"
	case assessment.Score >= 35:
		assessment.Level = "medium"
	case assessment.Score >= 15:
		assessment.Level = "low"
	default:
		assessment.Level = "info"
	}
	return assessment
}

func hasControl(asset model.Asset, controlType string) bool {
	for _, control := range asset.Controls {
		if control.Type == controlType {
			return true
		}
	}
	return false
}
func containsProduction(value string) bool { return productionToken.MatchString(value) }
func assetTargetsProduction(asset model.Asset) bool {
	for _, capability := range asset.Capabilities {
		if strings.EqualFold(capability.Environment, "production") || containsProduction(capability.Resource) {
			return true
		}
	}
	return false
}
