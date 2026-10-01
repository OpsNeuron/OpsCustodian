package audit

import (
	"testing"
)

func FuzzValidateEvent(f *testing.F) {
	valid := validSinkTestEvent()
	f.Add(valid.SchemaVersion, valid.Timestamp, valid.EventName, valid.SeverityNumber, valid.Body, "value")
	f.Add("unsupported", "not-a-time", " bad\n", 0, "", "")
	f.Add(SchemaVersion, "2026-10-01T00:00:00Z", "event", 24, "body", "attribute")

	f.Fuzz(func(t *testing.T, schema, timestamp, name string, severity int, body, attribute string) {
		if len(schema)+len(timestamp)+len(name)+len(body)+len(attribute) > 128<<10 {
			t.Skip()
		}
		event := Event{
			SchemaVersion:  schema,
			Timestamp:      timestamp,
			EventName:      name,
			SeverityNumber: severity,
			Body:           body,
			Resource: map[string]any{
				"service.name": "opscustodian",
			},
			InstrumentationScope: InstrumentationScope{Name: "opscustodian"},
			Attributes:           map[string]any{"fuzz.attribute": attribute},
		}
		firstErr := ValidateEvent(event)
		secondErr := ValidateEvent(event)
		if auditValidationErrorText(firstErr) != auditValidationErrorText(secondErr) {
			t.Fatalf("audit validation is not deterministic: %q != %q", auditValidationErrorText(firstErr), auditValidationErrorText(secondErr))
		}
	})
}

func auditValidationErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
