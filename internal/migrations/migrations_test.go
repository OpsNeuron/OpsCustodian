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
	if len(catalog) != 1 {
		t.Fatalf("migration count = %d, want 1", len(catalog))
	}
	migration := catalog[0]
	if migration.Version != 1 || migration.Name != "control_plane" || migration.Down == "" {
		t.Fatalf("unexpected migration: %#v", migration)
	}
	const checksum = "sha256:e1868d5f92ff2d917de4fa5cc15e1c8b9296bf3d52e9e02f1fd8521dd80f591a"
	if migration.Checksum != checksum {
		t.Fatalf("migration checksum changed: got %s; intentional SQL changes require a new migration", migration.Checksum)
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
		{name: "newer database", applied: map[int64]string{1: catalog[0].Checksum, 2: "sha256:future"}, contains: "compatible newer"},
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
