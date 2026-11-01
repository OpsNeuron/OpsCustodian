package audit

import (
	"math"
	"strings"
	"testing"
)

func TestValidateEventRejectsInvalidOrOversizedEnvelope(t *testing.T) {
	valid := validSinkTestEvent()
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "schema", mutate: func(event *Event) { event.SchemaVersion = "unsupported" }},
		{name: "event ID", mutate: func(event *Event) { event.EventID = "invalid" }},
		{name: "timestamp", mutate: func(event *Event) { event.Timestamp = "not-a-time" }},
		{name: "event name", mutate: func(event *Event) { event.EventName = " bad\n" }},
		{name: "severity", mutate: func(event *Event) { event.SeverityNumber = 25 }},
		{name: "missing resource", mutate: func(event *Event) { event.Resource = nil }},
		{name: "missing scope", mutate: func(event *Event) { event.InstrumentationScope.Name = "" }},
		{name: "invalid attribute key", mutate: func(event *Event) { event.Attributes[" bad\n"] = "value" }},
		{name: "nested attribute", mutate: func(event *Event) { event.Attributes["nested"] = map[string]any{"value": true} }},
		{name: "nested attribute array", mutate: func(event *Event) { event.Attributes["nested"] = [][]string{{"value"}} }},
		{name: "nil attribute", mutate: func(event *Event) { event.Attributes["nil"] = nil }},
		{name: "non JSON value", mutate: func(event *Event) { event.Attributes["invalid"] = math.NaN() }},
		{name: "oversized", mutate: func(event *Event) { event.Body = strings.Repeat("x", maxEventBytes) }},
	}
	if err := ValidateEvent(valid); err != nil {
		t.Fatalf("ValidateEvent(valid) error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validSinkTestEvent()
			test.mutate(&event)
			if err := ValidateEvent(event); err == nil {
				t.Fatal("invalid audit event was accepted")
			}
		})
	}
}

func TestEventIDIsDeterministicAndChangesWithContent(t *testing.T) {
	first := validSinkTestEvent()
	second := validSinkTestEvent()
	if first.EventID == "" || first.EventID != second.EventID {
		t.Fatalf("deterministic event IDs = %q and %q", first.EventID, second.EventID)
	}
	second.Attributes["opscustodian.credential.reload.result"] = "failed"
	second.EventID = deterministicEventID(second)
	if second.EventID == first.EventID {
		t.Fatalf("different event content retained ID %q", second.EventID)
	}
}
