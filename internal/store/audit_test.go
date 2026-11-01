package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/opscustodian/opscustodian/internal/audit"
)

func TestPostgresAuditMarksTransientStagesRetryableWithIdempotentCommit(t *testing.T) {
	event := audit.FromCredentialReload(audit.CredentialReloadObservation{
		OccurredAt: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), OrganizationID: "organization-0123456789abcdef", Succeeded: true,
	})

	beginDatabase := &fakePostgresDatabase{err: driver.ErrBadConn}
	postgres, err := newPostgresWriter(beginDatabase, "organization-0123456789abcdef", "Agent Platform")
	if err != nil {
		t.Fatal(err)
	}
	if err := postgres.Record(context.Background(), event); !audit.IsRetryableError(err) || !errors.Is(err, driver.ErrBadConn) {
		t.Fatalf("begin error = %v, retryable = %v", err, audit.IsRetryableError(err))
	}

	execFailure := &pgconn.PgError{Code: "40001", Message: "serialization failure"}
	execTransaction := &fakePostgresTransaction{execErrAt: 1, execErr: execFailure}
	postgres, _ = newPostgresWriter(&fakePostgresDatabase{transaction: execTransaction}, "organization-0123456789abcdef", "Agent Platform")
	if err := postgres.Record(context.Background(), event); !audit.IsRetryableError(err) || !errors.Is(err, execFailure) {
		t.Fatalf("exec error = %v, retryable = %v", err, audit.IsRetryableError(err))
	}

	commitFailure := &pgconn.PgError{Code: "08006", Message: "connection failure"}
	commitTransaction := &fakePostgresTransaction{commitErr: commitFailure}
	postgres, _ = newPostgresWriter(&fakePostgresDatabase{transaction: commitTransaction}, "organization-0123456789abcdef", "Agent Platform")
	if err := postgres.Record(context.Background(), event); !audit.IsRetryableError(err) || !errors.Is(err, commitFailure) {
		t.Fatalf("idempotent commit error = %v, retryable = %v", err, audit.IsRetryableError(err))
	}
}

func TestPostgresAuditInsertUsesTenantScopedIdempotencyKey(t *testing.T) {
	transaction := &fakePostgresTransaction{}
	postgres, err := newPostgresWriter(&fakePostgresDatabase{transaction: transaction}, "organization-0123456789abcdef", "Agent Platform")
	if err != nil {
		t.Fatal(err)
	}
	event := audit.FromCredentialReload(audit.CredentialReloadObservation{
		OccurredAt: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), OrganizationID: "organization-0123456789abcdef", Succeeded: true,
	})
	if err := postgres.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(transaction.statements) != 1 || len(transaction.statements[0].args) != 8 || transaction.statements[0].args[1] != event.EventID {
		t.Fatalf("audit insert statement = %#v", transaction.statements)
	}
	if !strings.Contains(transaction.statements[0].query, "ON CONFLICT (organization_id, event_id) DO NOTHING") {
		t.Fatalf("audit insert is not idempotent: %s", transaction.statements[0].query)
	}
}

func TestTransientPostgresAuditClassification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{name: "bad connection", err: driver.ErrBadConn, retryable: true},
		{name: "connection exception", err: &pgconn.PgError{Code: "08006"}, retryable: true},
		{name: "serialization", err: &pgconn.PgError{Code: "40001"}, retryable: true},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01"}, retryable: true},
		{name: "cannot connect", err: &pgconn.PgError{Code: "57P03"}, retryable: true},
		{name: "constraint", err: &pgconn.PgError{Code: "23505"}},
		{name: "cancelled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "plain", err: errors.New("permanent failure")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isTransientPostgresError(test.err); got != test.retryable {
				t.Fatalf("isTransientPostgresError() = %v, want %v", got, test.retryable)
			}
		})
	}
}

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
