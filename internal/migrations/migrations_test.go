package migrations

import (
	"context"
	"strings"
	"testing"
)

func TestCatalogIsContiguousPairedAndChecksumLocked(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog(): %v", err)
	}
	if len(catalog) != 3 {
		t.Fatalf("migration count = %d, want 3", len(catalog))
	}
	for _, migration := range catalog {
		if migration.Down == "" {
			t.Fatalf("migration has no rollback: %#v", migration)
		}
	}
	expected := []struct {
		version  int64
		name     string
		checksum string
	}{
		{1, "control_plane", "sha256:e1868d5f92ff2d917de4fa5cc15e1c8b9296bf3d52e9e02f1fd8521dd80f591a"},
		{2, "scheduler_leases", "sha256:328cc77fc86f492ed9721b3439a259f3289a2d18ff8d7455253586bd0f973f62"},
		{3, "audit_history", "sha256:ed85e031d05ebc954145a014ecde35db84e92153215c66cd0e2b27e5b06adc64"},
	}
	for index, value := range expected {
		migration := catalog[index]
		if migration.Version != value.version || migration.Name != value.name || migration.Checksum != value.checksum {
			t.Fatalf("migration %d changed: %#v; published SQL requires a new migration", index+1, migration)
		}
	}
}

func TestAuditHistorySchemaIsTenantScopedAndBounded(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	up := catalog[2].Up
	for _, required := range []string{
		"CREATE TABLE audit_events", "PRIMARY KEY (organization_id, id)",
		"REFERENCES organizations (id) ON DELETE CASCADE", "audit_events_timeline_idx",
		"audit_events_repository_timeline_idx", "jsonb_typeof(event) = 'object'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("audit history schema missing invariant %q", required)
		}
	}
}

func TestSchedulerLeaseSchemaEnforcesTenantFencingAndExpiry(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	up := catalog[1].Up
	for _, required := range []string{
		"CREATE TABLE scheduler_leases",
		"PRIMARY KEY (organization_id, name)",
		"fencing_token bigint NOT NULL CHECK (fencing_token > 0)",
		"REFERENCES organizations (id) ON DELETE CASCADE",
		"scheduler_leases_expiry_idx",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("scheduler lease schema missing invariant %q", required)
		}
	}
	if !strings.Contains(catalog[1].Down, "DROP TABLE IF EXISTS scheduler_leases") {
		t.Fatal("scheduler lease migration has no rollback")
	}
}

func TestInitialSchemaPreservesTenantAndImmutableSnapshotInvariants(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	up := catalog[0].Up
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS organizations",
		"PRIMARY KEY (organization_id, id)",
		"PRIMARY KEY (organization_id, repository_id, id)",
		"snapshots_bom_version CHECK",
		"snapshot_findings_severity CHECK",
		"snapshots_immutable_update",
		"snapshot_findings_immutable_update",
		"snapshots_repository_history_idx",
		"snapshot_findings_lifecycle_idx",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("initial schema missing invariant %q", required)
		}
	}
	if !strings.Contains(catalog[0].Down, "DROP TABLE IF EXISTS organizations") {
		t.Fatal("migration has no complete rollback")
	}
}

func TestRollbackRejectsUnsafeStepCountBeforeDatabaseAccess(t *testing.T) {
	if err := Rollback(context.Background(), nil, 0); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestValidateAppliedFailsClosedForTamperingAndNewerDatabases(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		applied  map[int64]string
		contains string
	}{
		{name: "valid", applied: map[int64]string{1: catalog[0].Checksum}},
		{name: "tampered", applied: map[int64]string{1: "sha256:changed"}, contains: "checksum mismatch"},
		{name: "newer database", applied: map[int64]string{1: catalog[0].Checksum, 2: catalog[1].Checksum, 3: catalog[2].Checksum, 4: "sha256:future"}, contains: "compatible newer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateApplied(catalog, test.applied)
			if test.contains == "" && err != nil {
				t.Fatalf("validateApplied() error = %v", err)
			}
			if test.contains != "" && (err == nil || !strings.Contains(err.Error(), test.contains)) {
				t.Fatalf("validateApplied() error = %v, want containing %q", err, test.contains)
			}
		})
	}
}
