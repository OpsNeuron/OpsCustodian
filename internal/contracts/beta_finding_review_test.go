package contracts_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/parsers/agentmarkdown"
	"github.com/opscustodian/opscustodian/internal/parsers/ghaw"
	"github.com/opscustodian/opscustodian/internal/parsers/githubactions"
	"github.com/opscustodian/opscustodian/internal/parsers/kubernetes"
	"github.com/opscustodian/opscustodian/internal/parsers/mcp"
	"github.com/opscustodian/opscustodian/internal/scanner"
)

type reviewedFinding struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Severity      string `json:"severity"`
	AssetID       string `json:"assetId"`
	Source        string `json:"source"`
	RemediationID string `json:"remediationId"`
	EvidenceCount int    `json:"evidenceCount"`
}

func TestBetaRepresentativeFindingReviewRemainsStable(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "scan-input")
	bom, err := scanner.Scan(context.Background(), scanner.Options{
		Root: root, Source: "github:OpsNeuron/OpsCustodian", Revision: "beta-review",
		Generator: "beta-finding-review",
		Parsers: []parsers.Parser{
			githubactions.Parser{}, ghaw.Parser{}, mcp.Parser{}, agentmarkdown.Parser{}, kubernetes.Parser{},
		},
	})
	if err != nil {
		t.Fatalf("scan representative fixture: %v", err)
	}

	assets := make(map[string]string, len(bom.Assets))
	for _, asset := range bom.Assets {
		assets[asset.ID] = asset.Source.Path
	}
	actual := make([]reviewedFinding, 0, len(bom.Findings))
	for _, finding := range bom.Findings {
		actual = append(actual, reviewedFinding{
			ID: finding.ID, Type: finding.Type, Severity: finding.Severity,
			AssetID: finding.AssetID, Source: assets[finding.AssetID],
			RemediationID: finding.RemediationID, EvidenceCount: len(finding.Evidence),
		})
	}

	content, err := os.ReadFile(filepath.Join("testdata", "beta-finding-review.json"))
	if err != nil {
		t.Fatalf("read reviewed finding set: %v", err)
	}
	var expected []reviewedFinding
	if err := json.Unmarshal(content, &expected); err != nil {
		t.Fatalf("decode reviewed finding set: %v", err)
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i].ID < actual[j].ID })
	sort.Slice(expected, func(i, j int) bool { return expected[i].ID < expected[j].ID })
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("representative finding set changed without review\nactual: %#v\nexpected: %#v", actual, expected)
	}
}
