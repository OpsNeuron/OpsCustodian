package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
)

func TestDiffFailOnExitContractAndReportPersistence(t *testing.T) {
	tempDir := t.TempDir()
	beforePath := filepath.Join(tempDir, "before.json")
	afterPath := filepath.Join(tempDir, "after.json")
	reportPath := filepath.Join(tempDir, "drift.json")

	asset := model.Asset{
		ID: "agent:reviewer", Type: "agent", Name: "reviewer",
		Source: model.Source{Path: ".github/agents/reviewer.md"},
		Evidence: []model.Evidence{{
			ID: "agent-definition", Path: ".github/agents/reviewer.md", Line: 1,
			Parser: "test", Confidence: "high",
		}},
	}
	before := testBOM("baseline", []model.Asset{asset})
	asset.Capabilities = []model.Capability{{
		Action: "github.issues.read", Resource: "github:acme/platform/issues", Effect: "read",
		EvidenceIDs: []string{"agent-definition"},
	}}
	after := testBOM("proposed", []model.Asset{asset})
	writeTestBOM(t, beforePath, before)
	writeTestBOM(t, afterPath, after)

	if err := Diff(DiffOptions{
		Before: beforePath, After: afterPath, Format: "json", Output: reportPath, FailOn: "high",
	}); err != nil {
		t.Fatalf("low-risk drift should not reach high threshold: %v", err)
	}

	err := Diff(DiffOptions{
		Before: beforePath, After: afterPath, Format: "json", Output: reportPath, FailOn: "LOW",
	})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("Diff() error = %#v, want ExitError code 2", err)
	}
	if !strings.Contains(exitErr.Error(), "semantic drift reached LOW threshold") {
		t.Fatalf("unexpected threshold error: %v", exitErr)
	}

	content, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("policy exit must preserve the generated report: %v", readErr)
	}
	var report drift.Report
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatalf("generated report is not valid JSON: %v", err)
	}
	if len(report.Changes) != 1 || report.Changes[0].Type != "capability-added" {
		t.Fatalf("unexpected generated report: %#v", report)
	}
}

func TestDiffRejectsUnknownFailOnSeverityBeforeIO(t *testing.T) {
	err := Diff(DiffOptions{Before: "missing-before.json", After: "missing-after.json", FailOn: "urgent"})
	if err == nil || !strings.Contains(err.Error(), `unsupported fail-on severity "urgent"`) {
		t.Fatalf("Diff() error = %v, want unsupported severity", err)
	}
	if strings.Contains(err.Error(), "read baseline") {
		t.Fatalf("fail-on validation should happen before filesystem access: %v", err)
	}
}

func TestDiffAccessPathFixtureAcrossJSONTerminalSARIFAndThreshold(t *testing.T) {
	before := filepath.Join("..", "..", "examples", "access-path-drift", "agentbom.before.json")
	after := filepath.Join("..", "..", "examples", "access-path-drift", "agentbom.after.json")
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "drift.json")

	err := Diff(DiffOptions{Before: before, After: after, Format: "json", Output: jsonPath, FailOn: "critical"})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("critical access path drift error = %#v, want ExitError code 2", err)
	}
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("critical threshold must preserve JSON report: %v", err)
	}
	var value drift.Report
	if err := json.Unmarshal(content, &value); err != nil {
		t.Fatalf("decode access path drift report: %v", err)
	}
	wantTypes := map[string]bool{"access-path-added": false, "access-path-escalated": false, "access-path-rerouted": false, "access-path-removed": false}
	for _, change := range value.Changes {
		if _, exists := wantTypes[change.Type]; exists {
			wantTypes[change.Type] = true
		}
		if change.ID == "" || len(change.Locations) == 0 {
			t.Fatalf("finding lacks stable ID or evidence location: %#v", change)
		}
	}
	for changeType, found := range wantTypes {
		if !found {
			t.Fatalf("missing %s in %#v", changeType, value.Changes)
		}
	}

	for _, format := range []string{"terminal", "sarif"} {
		outputPath := filepath.Join(tempDir, "drift."+format)
		if err := Diff(DiffOptions{Before: before, After: after, Format: format, Output: outputPath}); err != nil {
			t.Fatalf("%s diff failed: %v", format, err)
		}
		output, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read %s output: %v", format, err)
		}
		for changeType := range wantTypes {
			if !strings.Contains(string(output), changeType) {
				t.Fatalf("%s output does not contain %s", format, changeType)
			}
		}
	}
}

func TestDiffMCPFixtureAcrossJSONTerminalSARIFAndThreshold(t *testing.T) {
	before := filepath.Join("..", "..", "examples", "mcp-drift", "agentbom.before.json")
	after := filepath.Join("..", "..", "examples", "mcp-drift", "agentbom.after.json")
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "mcp-drift.json")

	err := Diff(DiffOptions{Before: before, After: after, Format: "json", Output: jsonPath, FailOn: "critical"})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("critical MCP drift error = %#v, want ExitError code 2", err)
	}
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("critical threshold must preserve MCP JSON report: %v", err)
	}
	var value drift.Report
	if err := json.Unmarshal(content, &value); err != nil {
		t.Fatalf("decode MCP drift report: %v", err)
	}
	want := map[string]int{"mcp-runtime-pin-weakened": 2, "mcp-transport-downgraded": 1, "mcp-repository-boundary-escaped": 1}
	for _, change := range value.Changes {
		if _, exists := want[change.Type]; exists {
			want[change.Type]--
		}
		if change.ID == "" || len(change.Locations) == 0 {
			t.Fatalf("MCP finding lacks stable ID or location: %#v", change)
		}
	}
	for changeType, remaining := range want {
		if remaining != 0 {
			t.Fatalf("MCP finding count for %s differs by %d: %#v", changeType, remaining, value.Changes)
		}
	}

	for _, format := range []string{"terminal", "sarif"} {
		outputPath := filepath.Join(tempDir, "mcp-drift."+format)
		if err := Diff(DiffOptions{Before: before, After: after, Format: format, Output: outputPath}); err != nil {
			t.Fatalf("MCP %s diff failed: %v", format, err)
		}
		output, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read MCP %s output: %v", format, err)
		}
		for changeType := range want {
			if !strings.Contains(string(output), changeType) {
				t.Fatalf("MCP %s output does not contain %s", format, changeType)
			}
		}
	}
}

func TestExitErrorPreservesCause(t *testing.T) {
	cause := errors.New("policy denied")
	err := &ExitError{Code: 2, Err: cause}
	if err.Error() != cause.Error() || !errors.Is(err, cause) {
		t.Fatalf("ExitError does not preserve its cause: %#v", err)
	}
}

func TestEventsWritesJSONLFromPersistedDrift(t *testing.T) {
	tempDir := t.TempDir()
	driftPath := filepath.Join(tempDir, "drift.json")
	eventsPath := filepath.Join(tempDir, "events.jsonl")
	before := filepath.Join("..", "..", "examples", "mcp-drift", "agentbom.before.json")
	after := filepath.Join("..", "..", "examples", "mcp-drift", "agentbom.after.json")
	if err := Diff(DiffOptions{Before: before, After: after, Format: "json", Output: driftPath}); err != nil {
		t.Fatalf("create persisted drift fixture: %v", err)
	}
	when := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	if err := Events(EventsOptions{Drift: driftPath, Output: eventsPath, OccurredAt: when}); err != nil {
		t.Fatalf("Events() error: %v", err)
	}
	content, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events output: %v", err)
	}
	if strings.Count(strings.TrimSpace(string(content)), "\n")+1 != 5 || !strings.Contains(string(content), `"eventName":"opscustodian.drift.detected"`) || !strings.Contains(string(content), `"eventName":"opscustodian.diff.completed"`) {
		t.Fatalf("unexpected JSONL events: %s", content)
	}
	if err := Events(EventsOptions{Output: eventsPath}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("Events() accepted no input: %v", err)
	}
	if err := Events(EventsOptions{BOM: before, Drift: driftPath, Output: eventsPath}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("Events() accepted two inputs: %v", err)
	}
}

func testBOM(revision string, assets []model.Asset) model.AgentBOM {
	return model.AgentBOM{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata: model.DocumentMetadata{
			Source: "github:acme/platform", Revision: revision,
		},
		Assets: assets,
	}
}

func writeTestBOM(t *testing.T, path string, bom model.AgentBOM) {
	t.Helper()
	content, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
