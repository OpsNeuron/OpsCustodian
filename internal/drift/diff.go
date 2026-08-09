package drift

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/opscustodian/opscustodian/internal/model"
)

type Change struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	AgentID  string `json:"agentId"`
	Subject  string `json:"subject"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Reason   string `json:"reason"`
}

type Report struct {
	BeforeRevision string   `json:"beforeRevision"`
	AfterRevision  string   `json:"afterRevision"`
	Changes        []Change `json:"changes"`
}

func Compare(before, after model.AgentBOM) Report {
	report := Report{BeforeRevision: before.Metadata.Revision, AfterRevision: after.Metadata.Revision}
	oldAgents, newAgents := indexAgents(before.Agents), indexAgents(after.Agents)
	for id, current := range newAgents {
		previous, exists := oldAgents[id]
		if !exists {
			report.Changes = append(report.Changes, Change{
				Type: "agent-added", Severity: "medium", AgentID: id, Subject: current.Name,
				Reason: "a new agentic principal was introduced",
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
				Type: "agent-removed", Severity: "info", AgentID: id, Subject: previous.Name,
				Reason: "an agentic principal was removed",
			})
		}
	}
	for index := range report.Changes {
		report.Changes[index].ID = changeID(report.Changes[index])
	}
	sort.Slice(report.Changes, func(i, j int) bool {
		return severityRank(report.Changes[i].Severity) > severityRank(report.Changes[j].Severity) ||
			(report.Changes[i].Severity == report.Changes[j].Severity && report.Changes[i].AgentID+report.Changes[i].Subject < report.Changes[j].AgentID+report.Changes[j].Subject)
	})
	return report
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
		severity := capabilitySeverity(capability)
		changes = append(changes, Change{
			Type: "capability-added", Severity: severity, AgentID: after.ID,
			Subject: capability.Action, After: capability.Resource + " (" + capability.Effect + ")",
			Reason: "the agent gained a capability not present in the baseline",
		})
	}
	for _, capability := range oldValues {
		changes = append(changes, Change{
			Type: "capability-removed", Severity: "info", AgentID: after.ID,
			Subject: capability.Action, Before: capability.Resource + " (" + capability.Effect + ")",
			Reason: "a baseline capability is no longer present",
		})
	}
	return changes
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
			Type: "credential-added", Severity: "high", AgentID: after.ID,
			Subject: value.Reference, After: value.Type,
			Reason: "the agent gained a new credential reference",
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
			changes = append(changes, Change{
				Type: "control-changed", Severity: "high", AgentID: after.ID,
				Subject: value.Type, Before: fmt.Sprint(value.Value), After: newValue,
				Reason: "a baseline safety control changed value",
			})
			continue
		}
		changes = append(changes, Change{
			Type: "control-removed", Severity: "high", AgentID: after.ID,
			Subject: value.Type, Before: fmt.Sprint(value.Value),
			Reason: "a baseline safety control is no longer present",
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

func indexAgents(agents []model.Agent) map[string]model.Agent {
	result := make(map[string]model.Agent, len(agents))
	for _, agent := range agents {
		result[agent.ID] = agent
	}
	return result
}

func capabilityKey(value model.Capability) string {
	return value.Action + "\x00" + value.Resource + "\x00" + value.Effect + "\x00" + value.Environment
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
	case "critical": return 5
	case "high": return 4
	case "medium": return 3
	case "low": return 2
	default: return 1
	}
}
