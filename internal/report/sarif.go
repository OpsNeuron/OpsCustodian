package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/opscustodian/opscustodian/internal/drift"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool       `json:"tool"`
	AutomationDetails sarifAutomation `json:"automationDetails"`
	Results           []sarifResult   `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
	Properties       any          `json:"properties,omitempty"`
}
type sarifAutomation struct {
	ID string `json:"id"`
}
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          any               `json:"properties,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func writeSARIF(w io.Writer, value drift.Report) error {
	ruleTypes := map[string]struct{}{}
	for _, change := range value.Changes {
		ruleTypes[change.Type] = struct{}{}
	}
	types := make([]string, 0, len(ruleTypes))
	for value := range ruleTypes {
		types = append(types, value)
	}
	sort.Strings(types)
	ruleIndexes := make(map[string]int, len(types))
	rules := make([]sarifRule, 0, len(types))
	for index, value := range types {
		ruleIndexes[value] = index
		rules = append(rules, sarifRule{
			ID: value, Name: value,
			ShortDescription: sarifMessage{Text: humanRuleName(value)},
			Help:             sarifMessage{Text: "Review the effective agent access change and its source evidence before approval."},
			Properties:       map[string]any{"tags": []string{"security", "agentic-devops", "permission-drift"}},
		})
	}
	results := make([]sarifResult, 0, len(value.Changes))
	for _, change := range value.Changes {
		results = append(results, sarifResult{
			RuleID: change.Type, RuleIndex: ruleIndexes[change.Type], Level: sarifLevel(change.Severity),
			Message: sarifMessage{Text: sarifResultMessage(change)}, Locations: sarifLocations(change.Locations),
			PartialFingerprints: map[string]string{"opscustodianFindingId/v1": change.ID},
			Properties: map[string]any{
				"findingId": change.ID, "agentId": change.AgentID, "severity": change.Severity,
				"before": change.Before, "after": change.After, "reason": change.Reason,
				"riskScore": change.Risk.Score, "riskFactors": change.Risk.Factors,
			},
		})
	}
	log := sarifLog{
		Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "OpsCustodian", InformationURI: "https://github.com/OpsNeuron/OpsCustodian",
				SemanticVersion: "0.1.0-pre", Rules: rules,
			}},
			AutomationDetails: sarifAutomation{ID: "opscustodian/semantic-drift"}, Results: results,
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func sarifLocations(values []drift.Location) []sarifLocation {
	locations := make([]sarifLocation, 0, len(values))
	for _, value := range values {
		physical := sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(value.Path)}}
		if value.Line > 0 {
			physical.Region = &sarifRegion{StartLine: value.Line, StartColumn: value.Column}
		}
		locations = append(locations, sarifLocation{PhysicalLocation: physical})
	}
	return locations
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifResultMessage(change drift.Change) string {
	message := fmt.Sprintf("%s: %s. %s", change.AgentID, change.Subject, change.Reason)
	if change.After != "" {
		message += " New value: " + change.After + "."
	}
	return message
}

func humanRuleName(value string) string {
	names := map[string]string{
		"asset-added": "Agentic asset added", "asset-removed": "Agentic asset removed",
		"capability-added": "Agent capability added", "capability-removed": "Agent capability removed",
		"capability-escalated": "Agent capability escalated",
		"credential-added":     "Agent credential reference added", "control-removed": "Agent safety control removed",
		"control-changed":                           "Agent safety control changed",
		"relationship-added":                        "Agentic asset relationship added",
		"relationship-removed":                      "Agentic asset relationship removed",
		"access-path-added":                         "Effective access path added",
		"access-path-escalated":                     "Effective access path escalated",
		"access-path-rerouted":                      "Effective access path rerouted",
		"access-path-removed":                       "Effective access path removed",
		"mcp-runtime-changed":                       "MCP runtime changed",
		"mcp-runtime-pin-weakened":                  "MCP runtime pin weakened",
		"mcp-runtime-origin-changed":                "MCP runtime origin changed",
		"mcp-runtime-source-changed":                "MCP runtime source changed",
		"mcp-transport-downgraded":                  "MCP transport downgraded",
		"mcp-repository-boundary-escaped":           "MCP runtime escaped repository boundary",
		"kubernetes-effective-access-expansion":     "Kubernetes effective access exceeds declared access",
		"kubernetes-rbac-privilege-escalation":      "Kubernetes role can escalate privileges",
		"kubernetes-service-account-token-exposure": "Kubernetes workload receives a ServiceAccount token",
		"kubernetes-projected-token-risk":           "Projected ServiceAccount token has risky settings",
		"mcp-runtime-unpinned":                      "MCP runtime identity is mutable or unverified",
		"mcp-insecure-transport":                    "Remote MCP server does not use TLS",
		"mcp-repository-boundary-escape":            "MCP runtime executes outside the repository boundary",
	}
	if name, exists := names[value]; exists {
		return name
	}
	return value
}
