package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

var organizationIDPattern = regexp.MustCompile(`^organization-[0-9a-f]{16}$`)

const (
	upsertOrganizationSQL = `INSERT INTO organizations (id, display_name) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name`
	upsertRepositorySQL = `INSERT INTO repositories (organization_id, id, source) VALUES ($1, $2, $3)
ON CONFLICT (organization_id, id) DO UPDATE SET updated_at = now()`
	verifySnapshotSQL = `WITH inserted AS (
    INSERT INTO snapshots (organization_id, repository_id, id, revision, generated_at, api_version, normalization_version, bom)
    VALUES ($1, $2, $3, $4, NULLIF($5, '')::timestamptz, $6, NULLIF($7, ''), $8::jsonb)
    ON CONFLICT (organization_id, repository_id, id) DO NOTHING
    RETURNING 1
)
SELECT EXISTS (SELECT 1 FROM inserted) OR EXISTS (
    SELECT 1 FROM snapshots
    WHERE organization_id = $1 AND repository_id = $2 AND id = $3 AND bom = $8::jsonb
)`
	insertFindingSQL = `INSERT INTO snapshot_findings
    (organization_id, repository_id, snapshot_id, finding_id, finding_type, severity, asset_id, remediation_id, finding)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
ON CONFLICT (organization_id, repository_id, snapshot_id, finding_id) DO NOTHING`
)

type postgresDatabase interface {
	BeginTx(context.Context, *sql.TxOptions) (postgresTransaction, error)
	QueryContext(context.Context, string, ...any) (postgresRows, error)
	QueryRowContext(context.Context, string, ...any) postgresRow
}

type postgresTransaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) postgresRow
	Commit() error
	Rollback() error
}

type postgresRow interface {
	Scan(...any) error
}

type postgresRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}

type sqlDatabase struct{ value *sql.DB }
type sqlTransaction struct{ value *sql.Tx }

func (database sqlDatabase) BeginTx(ctx context.Context, options *sql.TxOptions) (postgresTransaction, error) {
	transaction, err := database.value.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return sqlTransaction{value: transaction}, nil
}
func (database sqlDatabase) QueryContext(ctx context.Context, query string, args ...any) (postgresRows, error) {
	return database.value.QueryContext(ctx, query, args...)
}
func (database sqlDatabase) QueryRowContext(ctx context.Context, query string, args ...any) postgresRow {
	return database.value.QueryRowContext(ctx, query, args...)
}
func (transaction sqlTransaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return transaction.value.ExecContext(ctx, query, args...)
}
func (transaction sqlTransaction) QueryRowContext(ctx context.Context, query string, args ...any) postgresRow {
	return transaction.value.QueryRowContext(ctx, query, args...)
}
func (transaction sqlTransaction) Commit() error   { return transaction.value.Commit() }
func (transaction sqlTransaction) Rollback() error { return transaction.value.Rollback() }

type Postgres struct {
	database                postgresDatabase
	organizationID          string
	organizationDisplayName string
}

type PostgresWriter = Postgres

func NewPostgresWriter(database *sql.DB, organizationID, displayName string) (*Postgres, error) {
	if database == nil {
		return nil, fmt.Errorf("PostgreSQL database is required")
	}
	return newPostgresWriter(sqlDatabase{value: database}, organizationID, displayName)
}

func NewPostgres(database *sql.DB, organizationID, displayName string) (*Postgres, error) {
	return NewPostgresWriter(database, organizationID, displayName)
}

func newPostgresWriter(database postgresDatabase, organizationID, displayName string) (*Postgres, error) {
	if !organizationIDPattern.MatchString(organizationID) {
		return nil, fmt.Errorf("invalid organization ID %q", organizationID)
	}
	if displayName == "" {
		return nil, fmt.Errorf("organization display name is required")
	}
	return &Postgres{database: database, organizationID: organizationID, organizationDisplayName: displayName}, nil
}

func (writer *Postgres) PutSnapshot(ctx context.Context, bom model.AgentBOM) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return Snapshot{}, fmt.Errorf("invalid Agent BOM: %s at %s", issues[0].Code, issues[0].Path)
	}
	bomJSON, err := json.Marshal(bom)
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode Agent BOM: %w", err)
	}
	repositoryID := RepositoryID(bom.Metadata.Source)
	snapshotID := SnapshotID(repositoryID, bom.Metadata.Revision)
	transaction, err := writer.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin snapshot transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, upsertOrganizationSQL, writer.organizationID, writer.organizationDisplayName); err != nil {
		return Snapshot{}, fmt.Errorf("ensure organization: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, upsertRepositorySQL, writer.organizationID, repositoryID, bom.Metadata.Source); err != nil {
		return Snapshot{}, fmt.Errorf("ensure repository: %w", err)
	}
	var accepted bool
	if err := transaction.QueryRowContext(ctx, verifySnapshotSQL,
		writer.organizationID, repositoryID, snapshotID, bom.Metadata.Revision, bom.Metadata.GeneratedAt,
		bom.APIVersion, bom.Metadata.NormalizationVersion, bomJSON,
	).Scan(&accepted); err != nil {
		return Snapshot{}, fmt.Errorf("store snapshot: %w", err)
	}
	if !accepted {
		return Snapshot{}, fmt.Errorf("snapshot %s conflicts with immutable content for revision %s", snapshotID, bom.Metadata.Revision)
	}
	for _, finding := range bom.Findings {
		findingJSON, err := json.Marshal(finding)
		if err != nil {
			return Snapshot{}, fmt.Errorf("encode finding %s: %w", finding.ID, err)
		}
		if _, err := transaction.ExecContext(ctx, insertFindingSQL,
			writer.organizationID, repositoryID, snapshotID, finding.ID, finding.Type,
			finding.Severity, finding.AssetID, finding.RemediationID, findingJSON,
		); err != nil {
			return Snapshot{}, fmt.Errorf("store finding %s: %w", finding.ID, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("commit snapshot: %w", err)
	}
	cloned, err := cloneBOM(bom)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{RepositoryID: repositoryID, SnapshotID: snapshotID, BOM: cloned}, nil
}
