package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/risk"
)

func TestFromBOMUsesGeneratedTimestampAndDeterministicDiagnostics(t *testing.T) {
	bom := model.AgentBOM{
		Metadata: model.DocumentMetadata{Source: "github:acme/platform", Revision: "abc123", GeneratedAt: "2026-08-18T10:00:00Z"},
		Assets:   []model.Asset{{ID: "agent:a"}}, Relationships: []model.Relationship{{ID: "r"}}, AccessPaths: []model.AccessPath{{ID: "p"}},
		Diagnostics: []model.Diagnostic{
			{Severity: "warning", Code: "Z_CODE", Path: "z.yml", Parser: "z", Message: "secret-value-must-not-be-exported"},
			{Severity: "error", Code: "A_CODE", Path: "a.yml", Parser: "a", Message: "another-secret"},
		},
	}
	events := FromBOM(bom, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(events) != 3 || events[0].EventName != "opscustodian.scan.completed" || events[1].Attributes["opscustodian.diagnostic.code"] != "A_CODE" {
		t.Fatalf("unexpected BOM events: %#v", events)
	}
	if events[0].Timestamp != "2026-08-18T10:00:00Z" || events[1].SeverityNumber != 17 || events[2].SeverityNumber != 13 {
		t.Fatalf("unexpected timestamp or severity mapping: %#v", events)
	}
	var output bytes.Buffer
	if err := WriteJSONLines(&output, events); err != nil {
		t.Fatalf("WriteJSONLines() error: %v", err)
	}
	if strings.Contains(output.String(), "secret-value") || strings.Contains(output.String(), "another-secret") {
		t.Fatalf("diagnostic message leaked into audit events: %s", output.String())
	}
	if lines := strings.Count(strings.TrimSpace(output.String()), "\n") + 1; lines != len(events) {
		t.Fatalf("JSONL line count = %d, want %d", lines, len(events))
	}
}

func TestFromHTTPRequestUsesSharedSecretSafeAuditEnvelope(t *testing.T) {
	event := FromHTTPRequest(HTTPRequestObservation{
		OccurredAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		RequestID:  "request-123", OrganizationID: "organization-0123456789abcdef",
		Method: "GET", Route: "GET /api/v1/repositories", Status: 401,
		DurationMillis: 12, Authentication: "rejected", Authorization: "unknown", Identity: "unknown",
	})
	if event.SchemaVersion != SchemaVersion || event.EventName != "opscustodian.http.request.completed" || event.SeverityNumber != 13 || event.Attributes["http.route"] != "GET /api/v1/repositories" || event.Attributes["opscustodian.authentication.result"] != "rejected" || event.Attributes["opscustodian.identity.id"] != "unknown" {
		t.Fatalf("HTTP audit event = %#v", event)
	}
	content, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Authorization", "cursor=", "Bearer ", "password"} {
		if strings.Contains(string(content), forbidden) {
			t.Fatalf("HTTP audit event contains forbidden data %q: %s", forbidden, content)
		}
	}
}

func TestFromCredentialReloadMinimizesFailureEvent(t *testing.T) {
	event := FromCredentialReload(CredentialReloadObservation{OccurredAt: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC), OrganizationID: "organization-0123456789abcdef", Succeeded: false})
	if event.EventName != "opscustodian.credential.reload.completed" || event.SeverityNumber != 13 || event.Attributes["opscustodian.credential.reload.result"] != "failed" || len(event.Attributes) != 2 {
		t.Fatalf("credential reload event = %#v", event)
	}
}

func TestFromDriftEmitsFindingAndSummaryWithoutSensitiveDiffValues(t *testing.T) {
	report := drift.Report{BeforeRevision: "baseline", AfterRevision: "proposed", Changes: []drift.Change{{
		ID: "finding-123", Type: "mcp-runtime-pin-weakened", Severity: "critical", AgentID: "mcp:server", Subject: "server",
		Before: "secret-before", After: "secret-after", Reason: "secret-reason",
		Locations: []drift.Location{{Path: ".mcp.json", Line: 4, Column: 2}},
		Risk:      risk.Assessment{Score: 95, Level: "critical", Factors: []risk.Factor{{Name: "mcp-pin-weakened", Score: 40, Reason: "details"}}},
	}}}
	events := FromDrift(report, time.Date(2026, 8, 18, 12, 0, 0, 123, time.UTC))
	if len(events) != 2 || events[0].EventName != "opscustodian.drift.detected" || events[1].EventName != "opscustodian.diff.completed" {
		t.Fatalf("unexpected drift events: %#v", events)
	}
	if events[0].SeverityNumber != 21 || events[0].Attributes["code.file.path"] != ".mcp.json" || events[1].Attributes["opscustodian.finding.critical.count"] != 1 {
		t.Fatalf("unexpected drift attributes: %#v", events)
	}
	var output bytes.Buffer
	if err := WriteJSONLines(&output, events); err != nil {
		t.Fatalf("WriteJSONLines() error: %v", err)
	}
	for _, forbidden := range []string{"secret-before", "secret-after", "secret-reason", "details"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("audit event contains forbidden drift detail %q: %s", forbidden, output.String())
		}
	}
}

func TestFromBOMEmitsMinimizedCurrentStateFinding(t *testing.T) {
	bom := model.AgentBOM{
		Metadata: model.DocumentMetadata{Source: "github:acme/platform", Revision: "abc123", GeneratedAt: "2026-08-18T10:00:00Z"},
		Findings: []model.Finding{{
			ID: "finding-123", Type: "kubernetes-effective-access-expansion", Severity: "critical", AssetID: "workload:agent",
			Title: "secret-title", Reason: "secret-reason", RemediationID: "kubernetes.reduce-access", Remediation: "secret-remediation",
			Evidence:   []model.FindingEvidence{{AssetID: "role:admin", EvidenceID: "evidence"}},
			Attributes: map[string]any{"secret-key": "secret-value"},
		}},
	}
	events := FromBOM(bom, time.Now())
	if len(events) != 2 || events[1].EventName != "opscustodian.finding.detected" || events[1].SeverityNumber != 21 || events[1].Attributes["opscustodian.finding.id"] != "finding-123" {
		t.Fatalf("unexpected current-state finding event: %#v", events)
	}
	if events[1].Attributes["opscustodian.remediation.id"] != "kubernetes.reduce-access" {
		t.Fatalf("finding event missing remediation identifier: %#v", events[1])
	}
	var output bytes.Buffer
	if err := WriteJSONLines(&output, events); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-title", "secret-reason", "secret-remediation", "secret-key", "secret-value"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("finding detail %q leaked into audit event: %s", forbidden, output.String())
		}
	}
}
