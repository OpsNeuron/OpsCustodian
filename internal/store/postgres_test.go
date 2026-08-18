package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/model"
)

var _ Reader = (*Postgres)(nil)
var _ Writer = (*Postgres)(nil)

type fakePostgresDatabase struct {
	transaction *fakePostgresTransaction
	err         error
	begun       bool
	rows        []postgresRows
	row         int
	rowValues   []postgresRow
	rowValue    int
	queryArgs   [][]any
	rowArgs     [][]any
}

func (database *fakePostgresDatabase) QueryContext(_ context.Context, _ string, args ...any) (postgresRows, error) {
	database.queryArgs = append(database.queryArgs, append([]any(nil), args...))
	if database.row >= len(database.rows) {
		return &fakePostgresRows{}, nil
	}
	value := database.rows[database.row]
	database.row++
	return value, nil
}

func (database *fakePostgresDatabase) QueryRowContext(_ context.Context, _ string, args ...any) postgresRow {
	database.rowArgs = append(database.rowArgs, append([]any(nil), args...))
	if database.rowValue >= len(database.rowValues) {
		return fakeValueRow{err: sql.ErrNoRows}
	}
	value := database.rowValues[database.rowValue]
	database.rowValue++
	return value
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

type fakeValueRow struct {
	values []any
	err    error
}

func (row fakeValueRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	return assignFakeValues(destinations, row.values)
}

type fakePostgresRows struct {
	values [][]any
	index  int
	err    error
	closed bool
}

func (rows *fakePostgresRows) Next() bool { return rows.index < len(rows.values) }
func (rows *fakePostgresRows) Scan(destinations ...any) error {
	if rows.index >= len(rows.values) {
		return errors.New("scan after end")
	}
	values := rows.values[rows.index]
	rows.index++
	return assignFakeValues(destinations, values)
}
func (rows *fakePostgresRows) Err() error   { return rows.err }
func (rows *fakePostgresRows) Close() error { rows.closed = true; return nil }

func assignFakeValues(destinations, values []any) error {
	if len(destinations) != len(values) {
		return errors.New("fake scan arity mismatch")
	}
	for index := range values {
		target := reflect.ValueOf(destinations[index])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return errors.New("fake scan destination is not a pointer")
		}
		target.Elem().Set(reflect.ValueOf(values[index]))
	}
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

func TestPostgresReaderDecodesAndPaginatesTenantScopedData(t *testing.T) {
	bom := postgresTestBOM()
	content, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	generated := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	database := &fakePostgresDatabase{
		rows: []postgresRows{
			&fakePostgresRows{values: [][]any{
				{"repository-0000000000000001", "github:acme/a", "a1", 2, 3, 1},
				{"repository-0000000000000002", "github:acme/b", "b1", 1, 1, 0},
			}},
			&fakePostgresRows{values: [][]any{{"snapshot-0000000000000001", "abc123", sql.NullTime{Time: generated, Valid: true}, 1, 1}}},
			&fakePostgresRows{values: [][]any{{RepositoryID(bom.Metadata.Source), bom.Metadata.Source, bom.Metadata.Revision, mustJSON(t, bom.Findings[0])}}},
			&fakePostgresRows{values: [][]any{{
				RepositoryID(bom.Metadata.Source), bom.Metadata.Source, bom.Findings[0].ID, "persisting",
				"a1", "abc123", sql.NullString{}, sql.NullTime{Time: generated.Add(-time.Hour), Valid: true},
				sql.NullTime{Time: generated, Valid: true}, sql.NullTime{}, 2, mustJSON(t, bom.Findings[0]),
			}}},
		},
		rowValues: []postgresRow{
			fakeValueRow{values: []any{true}},
			fakeValueRow{values: []any{"snapshot-0000000000000001", content}},
		},
	}
	reader, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	repositories, err := reader.ListRepositories(context.Background(), PageRequest{Limit: 1})
	if err != nil || len(repositories.Items) != 1 || repositories.NextCursor != "repository-0000000000000001" {
		t.Fatalf("ListRepositories() = %#v, %v", repositories, err)
	}
	history, err := reader.ListSnapshots(context.Background(), RepositoryID(bom.Metadata.Source), PageRequest{Limit: 10})
	if err != nil || len(history.Items) != 1 || history.Items[0].GeneratedAt != "2026-08-18T12:00:00Z" {
		t.Fatalf("ListSnapshots() = %#v, %v", history, err)
	}
	latest, err := reader.LatestSnapshot(context.Background(), RepositoryID(bom.Metadata.Source))
	if err != nil || latest.BOM.Metadata.Revision != "abc123" {
		t.Fatalf("LatestSnapshot() = %#v, %v", latest, err)
	}
	findings, err := reader.ListFindings(context.Background(), FindingFilter{Page: PageRequest{Limit: 10}})
	if err != nil || len(findings.Items) != 1 || findings.Items[0].Finding.ID != "finding-writer" {
		t.Fatalf("ListFindings() = %#v, %v", findings, err)
	}
	lifecycle, err := reader.ListFindingLifecycle(context.Background(), FindingLifecycleFilter{Page: PageRequest{Limit: 10}})
	if err != nil || len(lifecycle.Items) != 1 || lifecycle.Items[0].Status != "persisting" || lifecycle.Items[0].Occurrences != 2 {
		t.Fatalf("ListFindingLifecycle() = %#v, %v", lifecycle, err)
	}
	for _, arguments := range append(database.queryArgs, database.rowArgs...) {
		if len(arguments) == 0 || arguments[0] != "organization-0123456789abcdef" {
			t.Fatalf("query escaped tenant boundary: %#v", arguments)
		}
	}
}

func TestPostgresReaderRejectsMissingAndInvalidStoredSnapshots(t *testing.T) {
	bom := postgresTestBOM()
	bom.APIVersion = "unsupported/v2"
	invalid := mustJSON(t, bom)
	database := &fakePostgresDatabase{rowValues: []postgresRow{
		fakeValueRow{err: sql.ErrNoRows},
		fakeValueRow{values: []any{"snapshot-0000000000000001", invalid}},
	}}
	reader, err := newPostgresWriter(database, "organization-0123456789abcdef", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.LatestSnapshot(context.Background(), "repository-0000000000000001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing snapshot error = %v", err)
	}
	if _, err := reader.LatestSnapshot(context.Background(), "repository-0000000000000001"); err == nil || !strings.Contains(err.Error(), "stored Agent BOM is invalid") {
		t.Fatalf("invalid stored snapshot error = %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
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
