package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/model"
)

func WriteFindings(w io.Writer, bom model.AgentBOM, format string) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(struct {
			APIVersion string          `json:"apiVersion"`
			Source     string          `json:"source"`
			Revision   string          `json:"revision"`
			Findings   []model.Finding `json:"findings"`
		}{contracts.FindingsAPIVersion, bom.Metadata.Source, bom.Metadata.Revision, nonNilFindings(bom.Findings)})
	case "terminal":
		fmt.Fprintf(w, "OpsCustodian current-state findings: %s @ %s\n", bom.Metadata.Source, bom.Metadata.Revision)
		if len(bom.Findings) == 0 {
			fmt.Fprintln(w, "No current-state findings detected.")
			return nil
		}
		for _, finding := range bom.Findings {
			fmt.Fprintf(w, "\n%-8s %s [%s]\n", strings.ToUpper(finding.Severity), finding.Title, finding.ID)
			fmt.Fprintf(w, "  Asset:       %s\n", finding.AssetID)
			fmt.Fprintf(w, "  Type:        %s\n", finding.Type)
			fmt.Fprintf(w, "  Reason:      %s\n", finding.Reason)
			if finding.Remediation != "" {
				fmt.Fprintf(w, "  Remediation ID: %s\n", finding.RemediationID)
				fmt.Fprintf(w, "  Remediation: %s\n", finding.Remediation)
			}
		}
		return nil
	case "sarif":
		return writeFindingsSARIF(w, bom)
	default:
		return fmt.Errorf("unsupported findings format %q", format)
	}
}

func writeFindingsSARIF(w io.Writer, bom model.AgentBOM) error {
	types := make([]string, 0)
	seenTypes := map[string]struct{}{}
	for _, finding := range bom.Findings {
		if _, exists := seenTypes[finding.Type]; !exists {
			seenTypes[finding.Type] = struct{}{}
			types = append(types, finding.Type)
		}
	}
	sort.Strings(types)
	ruleIndexes, rules := map[string]int{}, make([]sarifRule, 0, len(types))
	for index, findingType := range types {
		ruleIndexes[findingType] = index
		rules = append(rules, sarifRule{
			ID: findingType, Name: findingType,
			ShortDescription: sarifMessage{Text: humanRuleName(findingType)},
			Help:             sarifMessage{Text: "Review the effective agent access and its source evidence before deployment."},
			Properties:       map[string]any{"tags": []string{"security", "agentic-devops", "effective-access"}},
		})
	}
	results := make([]sarifResult, 0, len(bom.Findings))
	for _, finding := range bom.Findings {
		results = append(results, sarifResult{
			RuleID: finding.Type, RuleIndex: ruleIndexes[finding.Type], Level: sarifLevel(finding.Severity),
			Message:             sarifMessage{Text: finding.AssetID + ": " + finding.Reason},
			Locations:           findingSARIFLocations(bom, finding.Evidence),
			PartialFingerprints: map[string]string{"opscustodianFindingId/v1": finding.ID},
			Properties:          map[string]any{"findingId": finding.ID, "assetId": finding.AssetID, "severity": finding.Severity, "remediationId": finding.RemediationID, "remediation": finding.Remediation, "attributes": finding.Attributes},
		})
	}
	log := sarifLog{Version: contracts.SARIFVersion, Schema: contracts.SARIFSchema, Runs: []sarifRun{{
		Tool:              sarifTool{Driver: sarifDriver{Name: "OpsCustodian", InformationURI: "https://github.com/OpsNeuron/OpsCustodian", SemanticVersion: "0.1.0-pre", Rules: rules}},
		AutomationDetails: sarifAutomation{ID: "opscustodian/current-state-findings"}, Results: results,
	}}}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func findingSARIFLocations(bom model.AgentBOM, references []model.FindingEvidence) []sarifLocation {
	assets := map[string]model.Asset{}
	for _, asset := range bom.Assets {
		assets[asset.ID] = asset
	}
	seen := map[string]struct{}{}
	locations := make([]sarifLocation, 0, len(references))
	for _, reference := range references {
		for _, evidence := range assets[reference.AssetID].Evidence {
			if evidence.ID != reference.EvidenceID {
				continue
			}
			key := evidence.Path + fmt.Sprintf(":%d:%d", evidence.Line, evidence.Column)
			if _, exists := seen[key]; exists {
				break
			}
			seen[key] = struct{}{}
			physical := sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(evidence.Path)}}
			if evidence.Line > 0 {
				physical.Region = &sarifRegion{StartLine: evidence.Line, StartColumn: evidence.Column}
			}
			locations = append(locations, sarifLocation{PhysicalLocation: physical})
			break
		}
	}
	return locations
}

func nonNilFindings(values []model.Finding) []model.Finding {
	if values == nil {
		return []model.Finding{}
	}
	return values
}
