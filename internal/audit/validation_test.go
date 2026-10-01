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
		{name: "timestamp", mutate: func(event *Event) { event.Timestamp = "not-a-time" }},
		{name: "event name", mutate: func(event *Event) { event.EventName = " bad\n" }},
		{name: "severity", mutate: func(event *Event) { event.SeverityNumber = 25 }},
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
