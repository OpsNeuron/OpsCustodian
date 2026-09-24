package store

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
)

func TestMemoryAuditRetentionPrunesOnlyBoundedExpiredEvents(t *testing.T) {
	memory := NewMemory()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for index, occurred := range []time.Time{now.Add(-48 * time.Hour), now.Add(-36 * time.Hour), now.Add(-time.Hour)} {
		event := audit.FromHTTPRequest(audit.HTTPRequestObservation{
			OccurredAt: occurred, RequestID: "request", OrganizationID: "organization-0123456789abcdef",
			Identity: "operator", Method: http.MethodGet, Route: "/api/v1/repositories", Status: http.StatusOK,
			Authentication: "authenticated", Authorization: "authorized", DurationMillis: int64(index),
		})
		if err := memory.Record(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := memory.PruneAuditEvents(context.Background(), now.Add(-24*time.Hour), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first prune = %d, %v", deleted, err)
	}
	deleted, err = memory.PruneAuditEvents(context.Background(), now.Add(-24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("second prune = %d, %v", deleted, err)
	}
	page, err := memory.ListAuditEvents(context.Background(), AuditFilter{Page: PageRequest{Limit: 10}})
	if err != nil || len(page.Items) != 1 || page.Items[0].Event.Timestamp != now.Add(-time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("retained audit events = %#v, %v", page, err)
	}
}
