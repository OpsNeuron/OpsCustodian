package audit

import (
	"testing"
	"time"
)

var benchmarkValidationError error

func BenchmarkAuditEventValidation(b *testing.B) {
	event := FromHTTPRequest(HTTPRequestObservation{
		OccurredAt:     time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC),
		RequestID:      "benchmark-request-0123456789abcdef",
		OrganizationID: "benchmark-organization",
		Method:         "GET",
		Route:          "/api/v1/repositories",
		Status:         200,
		DurationMillis: 8,
		Authentication: "authenticated",
		Authorization:  "authorized",
		Identity:       "benchmark-reader",
	})
	b.ReportAllocs()
	for b.Loop() {
		benchmarkValidationError = ValidateEvent(event)
	}
	if benchmarkValidationError != nil {
		b.Fatal(benchmarkValidationError)
	}
}
