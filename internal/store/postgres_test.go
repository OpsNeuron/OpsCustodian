package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

type fakePostgresDatabase struct {
	transaction *fakePostgresTransaction
	err         error
	begun       bool
}

func (database *fakePostgresDatabase) BeginTx(context.Context, *sql.TxOptions) (postgresTransaction, error) {
	database.begun = true
	if database.err != nil {
		return nil, database.err
	}
	return database.transaction, nil
}

type executedStatement struct {
	query string
	args  []any
}

type fakePostgresTransaction struct {
	statements []executedStatement
	accepted   bool
	rowErr     error
	execErrAt  int
	committed  bool
	rolledBack bool
}

func (transaction *fakePostgresTransaction) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	transaction.statements = append(transaction.statements, executedStatement{query: query, args: args})
	if transaction.execErrAt > 0 && len(transaction.statements) == transaction.execErrAt {
		return nil, errors.New("exec failed")
	}
	return fakeSQLResult(1), nil
}
func (transaction *fakePostgresTransaction) QueryRowContext(_ context.Context, query string, args ...any) postgresRow {
	transaction.statements = append(transaction.statements, executedStatement{query: query, args: args})
	return fakePostgresRow{accepted: transaction.accepted, err: transaction.rowErr}
}
func (transaction *fakePostgresTransaction) Commit() error { transaction.committed = true; return nil }
func (transaction *fakePostgresTransaction) Rollback() error {
	transaction.rolledBack = true
	return nil
}

type fakePostgresRow struct {
	accepted bool
	err      error
}

func (row fakePostgresRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	*(destinations[0].(*bool)) = row.accepted
	return nil
}

type fakeSQLResult int64

func (result fakeSQLResult) LastInsertId() (int64, error) { return 0, nil }
func (result fakeSQLResult) RowsAffected() (int64, error) { return int64(result), nil }

func TestPostgresWriterStoresValidatedImmutableSnapshotTransactionally(t *testing.T) {
	transaction := &fakePostgresTransaction{accepted: true}
	database := &fakePostgresDatabase{transaction: transaction}
	writer, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	bom := postgresTestBOM()
	snapshot, err := writer.PutSnapshot(context.Background(), bom)
	if err != nil {
		t.Fatalf("PutSnapshot(): %v", err)
	}
	if !database.begun || !transaction.committed || !transaction.rolledBack {
		t.Fatalf("unexpected transaction lifecycle: %#v", transaction)
	}
	if snapshot.RepositoryID != RepositoryID(bom.Metadata.Source) || snapshot.SnapshotID != SnapshotID(snapshot.RepositoryID, bom.Metadata.Revision) {
		t.Fatalf("unexpected snapshot identity: %#v", snapshot)
	}
	if len(transaction.statements) != 4 {
		t.Fatalf("statement count = %d, want organization, repository, snapshot, and finding", len(transaction.statements))
	}
	if !strings.Contains(transaction.statements[2].query, "ON CONFLICT") || !strings.Contains(transaction.statements[2].query, "snapshots") {
		t.Fatalf("snapshot statement is not idempotent: %s", transaction.statements[2].query)
	}
	if !strings.Contains(transaction.statements[3].query, "snapshot_findings") {
		t.Fatalf("finding projection was not stored: %s", transaction.statements[3].query)
	}
}

func TestPostgresWriterRejectsImmutableRevisionConflict(t *testing.T) {
	transaction := &fakePostgresTransaction{accepted: false}
	writer, err := newPostgresWriter(&fakePostgresDatabase{transaction: transaction}, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.PutSnapshot(context.Background(), postgresTestBOM())
	if err == nil || !strings.Contains(err.Error(), "conflicts with immutable content") {
		t.Fatalf("PutSnapshot() error = %v", err)
	}
	if transaction.committed || !transaction.rolledBack {
		t.Fatalf("conflicting snapshot transaction was not rolled back: %#v", transaction)
	}
}

func TestPostgresWriterValidatesBeforeDatabaseAccess(t *testing.T) {
	database := &fakePostgresDatabase{transaction: &fakePostgresTransaction{accepted: true}}
	writer, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.PutSnapshot(context.Background(), model.AgentBOM{}); err == nil || !strings.Contains(err.Error(), "invalid Agent BOM") {
		t.Fatalf("invalid BOM error = %v", err)
	}
	if database.begun {
		t.Fatal("database transaction began before input validation")
	}
	if _, err := newPostgresWriter(database, "invalid", "Acme"); err == nil {
		t.Fatal("invalid organization ID was accepted")
	}
	if _, err := newPostgresWriter(database, "organization-0123456789abcdef", ""); err == nil {
		t.Fatal("empty organization display name was accepted")
	}
}

func postgresTestBOM() model.AgentBOM {
	asset := model.Asset{
		ID: "agent:writer", Type: "agent", Name: "writer", Source: model.Source{Path: "AGENTS.md"},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "evidence", Path: "AGENTS.md", Parser: "test", Confidence: "high"}},
	}
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: "github:acme/platform", Revision: "abc123", GeneratedAt: "2026-08-18T12:00:00Z", NormalizationVersion: "v1alpha1"},
		Assets:   []model.Asset{asset}, Findings: []model.Finding{{
			ID: "finding-writer", Type: "test-finding", Severity: "high", AssetID: asset.ID,
			Title: "Test finding", Reason: "Test risk.", RemediationID: "test.fix", Remediation: "Fix it.",
			Evidence: []model.FindingEvidence{{AssetID: asset.ID, EvidenceID: "evidence"}},
		}},
	}
}
