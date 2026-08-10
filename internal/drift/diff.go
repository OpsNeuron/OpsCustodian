package drift

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/normalize"
	"github.com/opscustodian/opscustodian/internal/risk"
)

type Change struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	AgentID   string          `json:"agentId"`
	Subject   string          `json:"subject"`
	Before    string          `json:"before,omitempty"`
	After     string          `json:"after,omitempty"`
	Reason    string          `json:"reason"`
	Locations []Location      `json:"locations,omitempty"`
	Risk      risk.Assessment `json:"risk"`
}

type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Report struct {
	BeforeRevision string   `json:"beforeRevision"`
	AfterRevision  string   `json:"afterRevision"`
	Changes        []Change `json:"changes"`
}

func Compare(before, after model.AgentBOM) Report {
	report := Report{BeforeRevision: before.Metadata.Revision, AfterRevision: after.Metadata.Revision}
	oldAgents, newAgents := indexAgents(before.Assets), indexAgents(after.Assets)
	for id, current := range newAgents {
		previous, exists := oldAgents[id]
		if !exists {
			assessment := risk.AssetAdded(current)
			report.Changes = append(report.Changes, Change{
				Type: "asset-added", Severity: assessment.Level, AgentID: id, Subject: current.Name,
				Reason:    "a new agentic asset was introduced",
				Locations: agentLocations(current, nil),
				Risk:      assessment,
			})
			continue
		}
		report.Changes = append(report.Changes, compareCapabilities(previous, current)...)
		report.Changes = append(report.Changes, compareCredentials(previous, current)...)
		report.Changes = append(report.Changes, compareControls(previous, current)...)
	}
	for id, previous := range oldAgents {
		if _, exists := newAgents[id]; !exists {
			report.Changes = append(report.Changes, Change{
				Type: "asset-removed", Severity: "info", AgentID: id, Subject: previous.Name,
				Reason:    "an agentic asset was removed",
				Locations: agentLocations(previous, nil),
				Risk:      risk.Assessment{Score: 5, Level: "info", Factors: []risk.Factor{{Name: "asset-removed", Score: 5, Reason: "asset removal may affect automation availability"}}},
			})
		}
	}
	report.Changes = append(report.Changes, compareRelationships(before.Relationships, after.Relationships, oldAgents, newAgents)...)
	for index := range report.Changes {
		report.Changes[index].ID = changeID(report.Changes[index])
	}
	sort.Slice(report.Changes, func(i, j int) bool {
		return severityRank(report.Changes[i].Severity) > severityRank(report.Changes[j].Severity) ||
			(report.Changes[i].Severity == report.Changes[j].Severity && report.Changes[i].AgentID+report.Changes[i].Subject < report.Changes[j].AgentID+report.Changes[j].Subject)
	})
	return report
}

func compareRelationships(before, after []model.Relationship, oldAssets, newAssets map[string]model.Agent) []Change {
	oldValues := map[string]model.Relationship{}
	for _, relation := range before {
		if relationshipDriftSupported(relation) {
			oldValues[relation.ID] = relation
		}
	}
	var changes []Change
	for _, relation := range after {
		if !relationshipDriftSupported(relation) {
			continue
		}
		if _, sourceExisted := oldAssets[relation.From]; !sourceExisted {
			continue
		}
		if _, exists := oldValues[relation.ID]; exists {
			delete(oldValues, relation.ID)
			continue
		}
		assessment := risk.Relationship(relation, false)
		changes = append(changes, Change{
			Type: "relationship-added", Severity: assessment.Level, AgentID: relation.From,
			Subject: relation.Type, After: relation.To,
			Reason:    "the agentic asset gained a new graph relationship",
			Locations: agentLocations(newAssets[relation.From], relation.EvidenceIDs),
			Risk:      assessment,
		})
	}
	for _, relation := range oldValues {
		if _, sourceStillExists := newAssets[relation.From]; !sourceStillExists {
			continue
		}
		assessment := risk.Relationship(relation, true)
		changes = append(changes, Change{
			Type: "relationship-removed", Severity: assessment.Level, AgentID: relation.From,
			Subject: relation.Type, Before: relation.To,
			Reason:    "an agentic asset graph relationship was removed",
			Locations: agentLocations(oldAssets[relation.From], relation.EvidenceIDs),
			Risk:      assessment,
		})
	}
	return changes
}

func relationshipDriftSupported(relation model.Relationship) bool {
	return relation.Type != "uses-credential"
}

func compareCapabilities(before, after model.Agent) []Change {
	oldValues := map[string]model.Capability{}
	for _, capability := range before.Capabilities {
		oldValues[capabilityKey(capability)] = capability
	}
	var changes []Change
	for _, capability := range after.Capabilities {
		key := capabilityKey(capability)
		if _, exists := oldValues[key]; exists {
			delete(oldValues, key)
			continue
		}
		candidateKey, previous, effectExpanded, scopeExpanded, expansionReason, escalated := findEscalationCandidate(oldValues, capability)
		if escalated {
			delete(oldValues, candidateKey)
			assessment := risk.CapabilityEscalation(after, capability, effectExpanded, scopeExpanded)
			reasons := []string{}
			if effectExpanded {
				reasons = append(reasons, "capability effect increased from "+previous.Effect+" to "+capability.Effect)
			}
			if scopeExpanded {
				reasons = append(reasons, expansionReason)
			}
			changes = append(changes, Change{
				Type: "capability-escalated", Severity: assessment.Level, AgentID: after.ID,
				Subject: capability.Action,
				Before:  previous.Resource + " (" + previous.Effect + ")", After: capability.Resource + " (" + capability.Effect + ")",
				Reason: strings.Join(reasons, "; "), Locations: agentLocations(after, capability.EvidenceIDs), Risk: assessment,
			})
			continue
		}
		assessment := risk.Capability(after, capability)
		changes = append(changes, Change{
			Type: "capability-added", Severity: assessment.Level, AgentID: after.ID,
			Subject: capability.Action, After: capability.Resource + " (" + capability.Effect + ")",
			Reason:    "the agent gained a capability not present in the baseline",
			Locations: agentLocations(after, capability.EvidenceIDs),
			Risk:      assessment,
		})
	}
	for _, capability := range oldValues {
		changes = append(changes, Change{
			Type: "capability-removed", Severity: "info", AgentID: after.ID,
			Subject: capability.Action, Before: capability.Resource + " (" + capability.Effect + ")",
			Reason:    "a baseline capability is no longer present",
			Locations: agentLocations(before, capability.EvidenceIDs),
			Risk:      risk.Assessment{Score: 5, Level: "info", Factors: []risk.Factor{{Name: "capability-removed", Score: 5, Reason: "capability removal may affect automation behavior"}}},
		})
	}
	return changes
}

func findEscalationCandidate(values map[string]model.Capability, after model.Capability) (string, model.Capability, bool, bool, string, bool) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		before := values[key]
		if before.Action != after.Action {
			continue
		}
		scopeExpanded, scopeReason := normalize.ScopeExpanded(before.Scope, after.Scope)
		sameScope := before.Resource == after.Resource || scopesEqual(before.Scope, after.Scope)
		effectExpanded := normalize.EffectRank(after.Effect) > normalize.EffectRank(before.Effect)
		if (effectExpanded && sameScope) || scopeExpanded {
			return key, before, effectExpanded, scopeExpanded, scopeReason, true
		}
	}
	return "", model.Capability{}, false, false, "", false
}

func scopesEqual(left, right *model.Scope) bool {
	if left == nil || right == nil || left.Kind != right.Kind || left.Wildcard != right.Wildcard || len(left.Values) != len(right.Values) {
		return false
	}
	for index := range left.Values {
		if left.Values[index] != right.Values[index] {
			return false
		}
	}
	return true
}

func compareCredentials(before, after model.Agent) []Change {
	oldValues := map[string]struct{}{}
	for _, value := range before.Credentials {
		oldValues[value.Type+"\x00"+value.Reference] = struct{}{}
	}
	var changes []Change
	for _, value := range after.Credentials {
		key := value.Type + "\x00" + value.Reference
		if _, exists := oldValues[key]; exists {
			continue
		}
		changes = append(changes, Change{
			Type: "credential-added", Severity: risk.Credential(after, value).Level, AgentID: after.ID,
			Subject: value.Reference, After: value.Type,
			Reason:    "the agent gained a new credential reference",
			Locations: agentLocations(after, nil),
			Risk:      risk.Credential(after, value),
		})
	}
	return changes
}

func compareControls(before, after model.Agent) []Change {
	newTypes := map[string]string{}
	for _, value := range after.Controls {
		newTypes[value.Type] = fmt.Sprint(value.Value)
	}
	var changes []Change
	for _, value := range before.Controls {
		newValue, exists := newTypes[value.Type]
		if exists && newValue == fmt.Sprint(value.Value) {
			continue
		}
		if exists {
			assessment := risk.Control(value, false)
			changes = append(changes, Change{
				Type: "control-changed", Severity: assessment.Level, AgentID: after.ID,
				Subject: value.Type, Before: fmt.Sprint(value.Value), After: newValue,
				Reason:    "a baseline safety control changed value",
				Locations: agentLocations(after, nil),
				Risk:      assessment,
			})
			continue
		}
		assessment := risk.Control(value, true)
		changes = append(changes, Change{
			Type: "control-removed", Severity: assessment.Level, AgentID: after.ID,
			Subject: value.Type, Before: fmt.Sprint(value.Value),
			Reason:    "a baseline safety control is no longer present",
			Locations: agentLocations(before, nil),
			Risk:      assessment,
		})
	}
	return changes
}

func Find(report Report, id string) (Change, bool) {
	for _, change := range report.Changes {
		if change.ID == id {
			return change, true
		}
	}
	return Change{}, false
}

func changeID(change Change) string {
	value := change.Type + "\x00" + change.AgentID + "\x00" + change.Subject + "\x00" + change.Before + "\x00" + change.After
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("finding-%x", sum[:6])
}

func agentLocations(agent model.Agent, evidenceIDs []string) []Location {
	wanted := map[string]struct{}{}
	for _, id := range evidenceIDs {
		wanted[id] = struct{}{}
	}
	seen := map[string]struct{}{}
	var locations []Location
	for _, evidence := range agent.Evidence {
		if len(wanted) > 0 {
			if _, exists := wanted[evidence.ID]; !exists {
				continue
			}
		}
		key := fmt.Sprintf("%s:%d:%d", evidence.Path, evidence.Line, evidence.Column)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		locations = append(locations, Location{Path: evidence.Path, Line: evidence.Line, Column: evidence.Column})
	}
	if len(locations) == 0 && agent.Source.Path != "" {
		locations = append(locations, Location{Path: agent.Source.Path})
	}
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Path != locations[j].Path {
			return locations[i].Path < locations[j].Path
		}
		if locations[i].Line != locations[j].Line {
			return locations[i].Line < locations[j].Line
		}
		return locations[i].Column < locations[j].Column
	})
	return locations
}

func indexAgents(agents []model.Agent) map[string]model.Agent {
	result := make(map[string]model.Agent, len(agents))
	for _, agent := range agents {
		result[agent.ID] = agent
	}
	return result
}

func capabilityKey(value model.Capability) string {
	return value.Action + "\x00" + value.Resource + "\x00" + value.Effect + "\x00" + value.Environment + "\x00" + scopeKey(value.Scope)
}

func scopeKey(value *model.Scope) string {
	if value == nil {
		return ""
	}
	return value.Kind + "\x00" + strings.Join(value.Values, "\x00") + fmt.Sprintf("\x00%t", value.Wildcard)
}

func capabilitySeverity(value model.Capability) string {
	if value.Effect == "delete" || value.Effect == "admin" {
		return "critical"
	}
	if value.Effect == "write" || value.Environment == "production" {
		return "high"
	}
	if value.Effect == "execute" {
		return "medium"
	}
	return "low"
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
