package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestPostgresSchedulerLeaseLifecycleIsTenantScopedAndFenced(t *testing.T) {
	expires := time.Date(2026, 8, 23, 12, 1, 0, 0, time.UTC)
	database := &fakePostgresDatabase{rowValues: []postgresRow{
		fakeValueRow{values: []any{"instance-a", int64(7), expires}},
		fakeValueRow{values: []any{"instance-a", int64(7), expires.Add(time.Minute)}},
		fakeValueRow{values: []any{true}},
	}}
	writer, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	lease, acquired, err := writer.AcquireSchedulerLease(context.Background(), "repository-ingestion", "instance-a", time.Minute)
	if err != nil || !acquired || lease.FencingToken != 7 || lease.ExpiresAt != expires {
		t.Fatalf("AcquireSchedulerLease() = %#v, %v, %v", lease, acquired, err)
	}
	renewed, ok, err := writer.RenewSchedulerLease(context.Background(), lease, 2*time.Minute)
	if err != nil || !ok || renewed.FencingToken != lease.FencingToken || renewed.ExpiresAt != expires.Add(time.Minute) {
		t.Fatalf("RenewSchedulerLease() = %#v, %v, %v", renewed, ok, err)
	}
	released, err := writer.ReleaseSchedulerLease(context.Background(), renewed)
	if err != nil || !released {
		t.Fatalf("ReleaseSchedulerLease() = %v, %v", released, err)
	}

	if len(database.rowArgs) != 3 {
		t.Fatalf("query count = %d, want 3", len(database.rowArgs))
	}
	for _, arguments := range database.rowArgs {
		if arguments[0] != "organization-0123456789abcdef" {
			t.Fatalf("lease query escaped tenant boundary: %#v", arguments)
		}
	}
	if database.rowArgs[1][3] != int64(7) || database.rowArgs[2][3] != int64(7) {
		t.Fatalf("renew or release omitted fencing token: %#v", database.rowArgs)
	}
	if !strings.Contains(acquireSchedulerLeaseSQL, "expires_at <= now()") ||
		!strings.Contains(acquireSchedulerLeaseSQL, "fencing_token + 1") ||
		!strings.Contains(renewSchedulerLeaseSQL, "expires_at > now()") {
		t.Fatal("lease SQL does not fail closed on ownership transition or expiry")
	}
}

func TestPostgresSchedulerLeaseReportsContentionWithoutError(t *testing.T) {
	database := &fakePostgresDatabase{rowValues: []postgresRow{
		fakeValueRow{err: sql.ErrNoRows},
		fakeValueRow{err: sql.ErrNoRows},
		fakeValueRow{err: sql.ErrNoRows},
	}}
	writer, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	lease := SchedulerLease{Name: "repository-ingestion", HolderID: "instance-a", FencingToken: 3}
	if _, ok, err := writer.AcquireSchedulerLease(context.Background(), lease.Name, lease.HolderID, time.Minute); err != nil || ok {
		t.Fatalf("contended acquire = %v, %v", ok, err)
	}
	if _, ok, err := writer.RenewSchedulerLease(context.Background(), lease, time.Minute); err != nil || ok {
		t.Fatalf("lost renew = %v, %v", ok, err)
	}
	if ok, err := writer.ReleaseSchedulerLease(context.Background(), lease); err != nil || ok {
		t.Fatalf("stale release = %v, %v", ok, err)
	}
}

func TestPostgresSchedulerLeaseValidatesBeforeDatabaseAccess(t *testing.T) {
	database := &fakePostgresDatabase{}
	writer, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, holder string
		ttl          time.Duration
	}{
		{"Bad Name", "instance-a", time.Minute},
		{"repository-ingestion", "bad holder", time.Minute},
		{"repository-ingestion", "instance-a", time.Second},
	}
	for _, test := range tests {
		if _, _, err := writer.AcquireSchedulerLease(context.Background(), test.name, test.holder, test.ttl); err == nil {
			t.Fatalf("invalid lease input accepted: %#v", test)
		}
	}
	if len(database.rowArgs) != 0 {
		t.Fatal("database was accessed before lease input validation")
	}
}
