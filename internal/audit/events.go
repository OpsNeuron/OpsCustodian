package audit

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
)

const SchemaVersion = contracts.AuditEventAPIVersion

type Event struct {
	SchemaVersion        string               `json:"schemaVersion"`
	Timestamp            string               `json:"timestamp"`
	EventName            string               `json:"eventName"`
	SeverityNumber       int                  `json:"severityNumber"`
	Body                 string               `json:"body,omitempty"`
	Resource             map[string]any       `json:"resource"`
	InstrumentationScope InstrumentationScope `json:"instrumentationScope"`
	Attributes           map[string]any       `json:"attributes"`
}

type InstrumentationScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type HTTPRequestObservation struct {
	OccurredAt     time.Time
	RequestID      string
	OrganizationID string
	Method         string
	Route          string
	Status         int
	DurationMillis int64
	Authentication string
	Authorization  string
	Identity       string
}

type CredentialReloadObservation struct {
	OccurredAt     time.Time
	OrganizationID string
	Succeeded      bool
}

func FromCredentialReload(observation CredentialReloadObservation) Event {
	outcome, severity := "succeeded", 9
	if !observation.Succeeded {
		outcome, severity = "failed", 13
	}
	return newEvent(observation.OccurredAt.UTC().Format(time.RFC3339Nano), "opscustodian.credential.reload.completed", severity, "OpsCustodian credential reload completed", map[string]any{
		"opscustodian.organization.id":          observation.OrganizationID,
		"opscustodian.credential.reload.result": outcome,
	})
}

func FromHTTPRequest(observation HTTPRequestObservation) Event {
	severity := 9
	if observation.Status == 401 || observation.Status == 403 || observation.Status >= 500 {
		severity = 13
	}
	return newEvent(observation.OccurredAt.UTC().Format(time.RFC3339Nano), "opscustodian.http.request.completed", severity, "OpsCustodian control-plane HTTP request completed", map[string]any{
		"opscustodian.request.id":            observation.RequestID,
		"opscustodian.organization.id":       observation.OrganizationID,
		"opscustodian.authentication.result": observation.Authentication,
		"opscustodian.authorization.result":  observation.Authorization,
		"opscustodian.identity.id":           observation.Identity,
		"http.request.method":                observation.Method,
		"http.route":                         observation.Route,
		"http.response.status_code":          observation.Status,
		"http.server.request.duration_ms":    observation.DurationMillis,
	})
}

func FromBOM(bom model.AgentBOM, occurredAt time.Time) []Event {
	timestamp := eventTimestamp(bom.Metadata.GeneratedAt, occurredAt)
	events := []Event{newEvent(timestamp, "opscustodian.scan.completed", 9, "OpsCustodian repository scan completed", map[string]any{
		"opscustodian.source":             bom.Metadata.Source,
		"opscustodian.revision":           bom.Metadata.Revision,
		"opscustodian.asset.count":        len(bom.Assets),
		"opscustodian.relationship.count": len(bom.Relationships),
		"opscustodian.access_path.count":  len(bom.AccessPaths),
		"opscustodian.diagnostic.count":   len(bom.Diagnostics),
	})}
	diagnostics := append([]model.Diagnostic(nil), bom.Diagnostics...)
	sort.Slice(diagnostics, func(i, j int) bool {
		return diagnostics[i].Severity+"\x00"+diagnostics[i].Code+"\x00"+diagnostics[i].Path+"\x00"+diagnostics[i].Parser <
			diagnostics[j].Severity+"\x00"+diagnostics[j].Code+"\x00"+diagnostics[j].Path+"\x00"+diagnostics[j].Parser
	})
	for _, diagnostic := range diagnostics {
		events = append(events, newEvent(timestamp, "opscustodian.diagnostic.reported", severityNumber(diagnostic.Severity), "OpsCustodian scan diagnostic reported", map[string]any{
			"opscustodian.source":              bom.Metadata.Source,
			"opscustodian.revision":            bom.Metadata.Revision,
			"opscustodian.diagnostic.code":     diagnostic.Code,
			"opscustodian.diagnostic.severity": diagnostic.Severity,
			"opscustodian.parser.name":         diagnostic.Parser,
			"code.file.path":                   diagnostic.Path,
		}))
	}
	findings := append([]model.Finding(nil), bom.Findings...)
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	for _, finding := range findings {
		events = append(events, newEvent(timestamp, "opscustodian.finding.detected", severityNumber(finding.Severity), "OpsCustodian current-state finding detected", map[string]any{
			"opscustodian.source":           bom.Metadata.Source,
			"opscustodian.revision":         bom.Metadata.Revision,
			"opscustodian.finding.id":       finding.ID,
			"opscustodian.finding.type":     finding.Type,
			"opscustodian.finding.severity": finding.Severity,
			"opscustodian.remediation.id":   finding.RemediationID,
			"opscustodian.asset.id":         finding.AssetID,
			"opscustodian.location.count":   len(finding.Evidence),
		}))
	}
	return events
}

func FromDrift(report drift.Report, occurredAt time.Time) []Event {
	timestamp := occurredAt.UTC().Format(time.RFC3339Nano)
	counts := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	events := make([]Event, 0, len(report.Changes)+1)
	for _, change := range report.Changes {
		counts[change.Severity]++
		factorNames := make([]string, 0, len(change.Risk.Factors))
		for _, factor := range change.Risk.Factors {
			factorNames = append(factorNames, factor.Name)
		}
		sort.Strings(factorNames)
		attributes := map[string]any{
			"opscustodian.baseline.revision": report.BeforeRevision,
			"opscustodian.proposed.revision": report.AfterRevision,
			"opscustodian.finding.id":        change.ID,
			"opscustodian.finding.type":      change.Type,
			"opscustodian.finding.severity":  change.Severity,
			"opscustodian.asset.id":          change.AgentID,
			"opscustodian.finding.subject":   change.Subject,
			"opscustodian.risk.score":        change.Risk.Score,
			"opscustodian.risk.factors":      factorNames,
			"opscustodian.location.count":    len(change.Locations),
		}
		if len(change.Locations) > 0 {
			attributes["code.file.path"] = change.Locations[0].Path
			if change.Locations[0].Line > 0 {
				attributes["code.line.number"] = change.Locations[0].Line
			}
			if change.Locations[0].Column > 0 {
				attributes["code.column.number"] = change.Locations[0].Column
			}
		}
		events = append(events, newEvent(timestamp, "opscustodian.drift.detected", severityNumber(change.Severity), "OpsCustodian semantic drift detected", attributes))
	}
	events = append(events, newEvent(timestamp, "opscustodian.diff.completed", 9, "OpsCustodian semantic diff completed", map[string]any{
		"opscustodian.baseline.revision":      report.BeforeRevision,
		"opscustodian.proposed.revision":      report.AfterRevision,
		"opscustodian.finding.count":          len(report.Changes),
		"opscustodian.finding.info.count":     counts["info"],
		"opscustodian.finding.low.count":      counts["low"],
		"opscustodian.finding.medium.count":   counts["medium"],
		"opscustodian.finding.high.count":     counts["high"],
		"opscustodian.finding.critical.count": counts["critical"],
	}))
	return events
}

func WriteJSONLines(w io.Writer, events []Event) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func newEvent(timestamp, name string, severity int, body string, attributes map[string]any) Event {
	return Event{
		SchemaVersion: SchemaVersion, Timestamp: timestamp, EventName: name, SeverityNumber: severity, Body: body,
		Resource:             map[string]any{"service.name": "opscustodian", "service.namespace": "opscustodian.dev"},
		InstrumentationScope: InstrumentationScope{Name: "github.com/opscustodian/opscustodian/audit"},
		Attributes:           attributes,
	}
}

func eventTimestamp(generatedAt string, fallback time.Time) string {
	if value, err := time.Parse(time.RFC3339Nano, generatedAt); err == nil {
		return value.UTC().Format(time.RFC3339Nano)
	}
	return fallback.UTC().Format(time.RFC3339Nano)
}

func severityNumber(value string) int {
	switch value {
	case "critical":
		return 21
	case "high", "error":
		return 17
	case "medium", "warning", "warn":
		return 13
	case "low":
		return 10
	default:
		return 9
	}
}
