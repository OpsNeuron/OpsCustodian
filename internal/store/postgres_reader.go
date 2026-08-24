package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

const listRepositoriesSQL = `
SELECT r.id, r.source, latest.revision,
       (SELECT count(*) FROM snapshots history WHERE history.organization_id = r.organization_id AND history.repository_id = r.id),
       CASE WHEN jsonb_typeof(latest.bom -> 'assets') = 'array' THEN jsonb_array_length(latest.bom -> 'assets') ELSE 0 END,
       CASE WHEN jsonb_typeof(latest.bom -> 'findings') = 'array' THEN jsonb_array_length(latest.bom -> 'findings') ELSE 0 END
FROM repositories r
JOIN LATERAL (
    SELECT revision, bom FROM snapshots
    WHERE organization_id = r.organization_id AND repository_id = r.id
    ORDER BY ingested_at DESC, id DESC LIMIT 1
) latest ON true
WHERE r.organization_id = $1 AND r.id > $2
ORDER BY r.id
LIMIT $3`

const repositoryExistsSQL = `SELECT EXISTS (
    SELECT 1 FROM repositories WHERE organization_id = $1 AND id = $2
)`

const latestSnapshotSQL = `SELECT id, bom FROM snapshots
WHERE organization_id = $1 AND repository_id = $2
ORDER BY ingested_at DESC, id DESC LIMIT 1`

const snapshotSQL = `SELECT id, bom FROM snapshots
WHERE organization_id = $1 AND repository_id = $2 AND id = $3`

const listSnapshotsSQL = `SELECT id, revision, generated_at,
       CASE WHEN jsonb_typeof(bom -> 'assets') = 'array' THEN jsonb_array_length(bom -> 'assets') ELSE 0 END,
       CASE WHEN jsonb_typeof(bom -> 'findings') = 'array' THEN jsonb_array_length(bom -> 'findings') ELSE 0 END
FROM snapshots
WHERE organization_id = $1 AND repository_id = $2
  AND (COALESCE(generated_at, '-infinity'::timestamptz), id) >
      (COALESCE(NULLIF($3, '')::timestamptz, '-infinity'::timestamptz), $4)
ORDER BY COALESCE(generated_at, '-infinity'::timestamptz), id
LIMIT $5`

const listFindingsSQL = `WITH latest AS (
    SELECT DISTINCT ON (repository_id) repository_id, id AS snapshot_id, revision
    FROM snapshots WHERE organization_id = $1
    ORDER BY repository_id, ingested_at DESC, id DESC
)
SELECT r.id, r.source, latest.revision, findings.finding
FROM latest
JOIN repositories r ON r.organization_id = $1 AND r.id = latest.repository_id
JOIN snapshot_findings findings ON findings.organization_id = $1
    AND findings.repository_id = latest.repository_id AND findings.snapshot_id = latest.snapshot_id
WHERE ($2 = '' OR r.id = $2) AND ($3 = '' OR findings.severity = $3)
  AND (r.id, findings.finding_id) > ($4, $5)
ORDER BY r.id, findings.finding_id
LIMIT $6`

const listFindingLifecycleSQL = `WITH ordered_snapshots AS (
    SELECT repository_id, id AS snapshot_id, revision, generated_at,
           row_number() OVER (PARTITION BY repository_id ORDER BY ingested_at, id) AS sequence
    FROM snapshots
    WHERE organization_id = $1 AND ($2 = '' OR repository_id = $2)
), presence AS (
    SELECT snapshots.repository_id, snapshots.snapshot_id, snapshots.revision, snapshots.generated_at,
           snapshots.sequence, findings.finding_id, findings.severity, findings.finding,
           lag(snapshots.sequence) OVER (
               PARTITION BY snapshots.repository_id, findings.finding_id ORDER BY snapshots.sequence
           ) AS previous_sequence
    FROM ordered_snapshots snapshots
    JOIN snapshot_findings findings ON findings.organization_id = $1
        AND findings.repository_id = snapshots.repository_id AND findings.snapshot_id = snapshots.snapshot_id
), numbered AS (
    SELECT *, sum(CASE WHEN previous_sequence IS NULL OR sequence <> previous_sequence + 1 THEN 1 ELSE 0 END)
        OVER (PARTITION BY repository_id, finding_id ORDER BY sequence) AS episode
    FROM presence
), episodes AS (
    SELECT repository_id, finding_id, episode, min(sequence) AS first_sequence, max(sequence) AS last_sequence,
           count(*)::int AS occurrences,
           (array_agg(revision ORDER BY sequence))[1] AS first_revision,
           (array_agg(revision ORDER BY sequence DESC))[1] AS last_revision,
           (array_agg(generated_at ORDER BY sequence))[1] AS first_observed_at,
           (array_agg(generated_at ORDER BY sequence DESC))[1] AS last_observed_at,
           (array_agg(severity ORDER BY sequence DESC))[1] AS severity,
           (array_agg(finding ORDER BY sequence DESC))[1] AS finding,
           row_number() OVER (PARTITION BY repository_id, finding_id ORDER BY episode DESC) AS episode_rank
    FROM numbered GROUP BY repository_id, finding_id, episode
), latest_sequences AS (
    SELECT repository_id, max(sequence) AS latest_sequence FROM ordered_snapshots GROUP BY repository_id
), current_episodes AS (
    SELECT episodes.*, repositories.source, resolved.revision AS resolved_revision,
           resolved.generated_at AS resolved_at,
           CASE WHEN episodes.last_sequence < latest_sequences.latest_sequence THEN 'resolved'
                WHEN episodes.occurrences = 1 THEN 'introduced' ELSE 'persisting' END AS status
    FROM episodes
    JOIN latest_sequences USING (repository_id)
    JOIN repositories ON repositories.organization_id = $1 AND repositories.id = episodes.repository_id
    LEFT JOIN ordered_snapshots resolved ON resolved.repository_id = episodes.repository_id
        AND resolved.sequence = episodes.last_sequence + 1
    WHERE episodes.episode_rank = 1
)
SELECT repository_id, source, finding_id, status, first_revision, last_revision,
       resolved_revision, first_observed_at, last_observed_at, resolved_at, occurrences, finding
FROM current_episodes
WHERE ($3 = '' OR severity = $3) AND ($4 = '' OR status = $4)
  AND (repository_id, finding_id) > ($5, $6)
ORDER BY repository_id, finding_id
LIMIT $7`

func (store *Postgres) ListRepositories(ctx context.Context, page PageRequest) (RepositoryPage, error) {
	limit := normalizedPageLimit(page.Limit)
	rows, err := store.database.QueryContext(ctx, listRepositoriesSQL, store.organizationID, page.Cursor, limit+1)
	if err != nil {
		return RepositoryPage{}, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()
	items := make([]RepositorySummary, 0, limit+1)
	for rows.Next() {
		var item RepositorySummary
		if err := rows.Scan(&item.ID, &item.Source, &item.LatestRevision, &item.SnapshotCount, &item.AssetCount, &item.FindingCount); err != nil {
			return RepositoryPage{}, fmt.Errorf("scan repository: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return RepositoryPage{}, err
	}
	items, next := databasePage(items, limit, func(item RepositorySummary) string { return item.ID })
	return RepositoryPage{Items: items, NextCursor: next}, nil
}

func (store *Postgres) LatestSnapshot(ctx context.Context, repositoryID string) (Snapshot, error) {
	return store.readSnapshot(ctx, latestSnapshotSQL, repositoryID)
}

func (store *Postgres) Snapshot(ctx context.Context, repositoryID, snapshotID string) (Snapshot, error) {
	return store.readSnapshot(ctx, snapshotSQL, repositoryID, snapshotID)
}

func (store *Postgres) readSnapshot(ctx context.Context, query, repositoryID string, extra ...any) (Snapshot, error) {
	args := []any{store.organizationID, repositoryID}
	args = append(args, extra...)
	var snapshotID string
	var content []byte
	if err := store.database.QueryRowContext(ctx, query, args...).Scan(&snapshotID, &content); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Snapshot{}, ErrNotFound
		}
		return Snapshot{}, fmt.Errorf("read snapshot: %w", err)
	}
	bom, err := decodeStoredBOM(content)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{RepositoryID: repositoryID, SnapshotID: snapshotID, BOM: bom}, nil
}

func (store *Postgres) ListSnapshots(ctx context.Context, repositoryID string, page PageRequest) (SnapshotPage, error) {
	var exists bool
	if err := store.database.QueryRowContext(ctx, repositoryExistsSQL, store.organizationID, repositoryID).Scan(&exists); err != nil {
		return SnapshotPage{}, fmt.Errorf("inspect repository: %w", err)
	}
	if !exists {
		return SnapshotPage{}, ErrNotFound
	}
	generatedAt, snapshotID := splitCompositeCursor(page.Cursor)
	limit := normalizedPageLimit(page.Limit)
	rows, err := store.database.QueryContext(ctx, listSnapshotsSQL, store.organizationID, repositoryID, generatedAt, snapshotID, limit+1)
	if err != nil {
		return SnapshotPage{}, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()
	items := make([]SnapshotSummary, 0, limit+1)
	for rows.Next() {
		var item SnapshotSummary
		var timestamp sql.NullTime
		if err := rows.Scan(&item.ID, &item.Revision, &timestamp, &item.AssetCount, &item.FindingCount); err != nil {
			return SnapshotPage{}, err
		}
		item.RepositoryID = repositoryID
		item.GeneratedAt = formatNullTime(timestamp)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return SnapshotPage{}, err
	}
	items, next := databasePage(items, limit, snapshotSortKey)
	return SnapshotPage{Items: items, NextCursor: next}, nil
}

func (store *Postgres) ListFindings(ctx context.Context, filter FindingFilter) (FindingPage, error) {
	cursorRepository, cursorFinding := splitCompositeCursor(filter.Page.Cursor)
	limit := normalizedPageLimit(filter.Page.Limit)
	rows, err := store.database.QueryContext(ctx, listFindingsSQL,
		store.organizationID, filter.RepositoryID, filter.Severity, cursorRepository, cursorFinding, limit+1,
	)
	if err != nil {
		return FindingPage{}, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	items := make([]FindingRecord, 0, limit+1)
	for rows.Next() {
		var item FindingRecord
		var content []byte
		if err := rows.Scan(&item.RepositoryID, &item.Source, &item.Revision, &content); err != nil {
			return FindingPage{}, err
		}
		if err := json.Unmarshal(content, &item.Finding); err != nil {
			return FindingPage{}, fmt.Errorf("decode finding: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return FindingPage{}, err
	}
	items, next := databasePage(items, limit, findingSortKey)
	return FindingPage{Items: items, NextCursor: next}, nil
}

func (store *Postgres) ListFindingLifecycle(ctx context.Context, filter FindingLifecycleFilter) (FindingLifecyclePage, error) {
	cursorRepository, cursorFinding := splitCompositeCursor(filter.Page.Cursor)
	limit := normalizedPageLimit(filter.Page.Limit)
	rows, err := store.database.QueryContext(ctx, listFindingLifecycleSQL,
		store.organizationID, filter.RepositoryID, filter.Severity, filter.Status,
		cursorRepository, cursorFinding, limit+1,
	)
	if err != nil {
		return FindingLifecyclePage{}, fmt.Errorf("list finding lifecycle: %w", err)
	}
	defer rows.Close()
	items := make([]FindingLifecycleRecord, 0, limit+1)
	for rows.Next() {
		var item FindingLifecycleRecord
		var resolvedRevision sql.NullString
		var firstObserved, lastObserved, resolvedAt sql.NullTime
		var content []byte
		if err := rows.Scan(
			&item.RepositoryID, &item.Source, &item.FindingID, &item.Status,
			&item.FirstRevision, &item.LastRevision, &resolvedRevision,
			&firstObserved, &lastObserved, &resolvedAt, &item.Occurrences, &content,
		); err != nil {
			return FindingLifecyclePage{}, err
		}
		item.ResolvedRevision = resolvedRevision.String
		item.FirstObservedAt, item.LastObservedAt, item.ResolvedAt = formatNullTime(firstObserved), formatNullTime(lastObserved), formatNullTime(resolvedAt)
		if err := json.Unmarshal(content, &item.Finding); err != nil {
			return FindingLifecyclePage{}, fmt.Errorf("decode lifecycle finding: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return FindingLifecyclePage{}, err
	}
	items, next := databasePage(items, limit, lifecycleSortKey)
	return FindingLifecyclePage{Items: items, NextCursor: next}, nil
}

func decodeStoredBOM(content []byte) (model.AgentBOM, error) {
	var bom model.AgentBOM
	if err := json.Unmarshal(content, &bom); err != nil {
		return model.AgentBOM{}, fmt.Errorf("decode stored Agent BOM: %w", err)
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return model.AgentBOM{}, fmt.Errorf("stored Agent BOM is invalid: %s at %s", issues[0].Code, issues[0].Path)
	}
	return bom, nil
}

func normalizedPageLimit(limit int) int {
	if limit < 1 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func splitCompositeCursor(cursor string) (string, string) {
	left, right, _ := strings.Cut(cursor, "\x00")
	return left, right
}

func databasePage[T any](items []T, limit int, key func(T) string) ([]T, string) {
	if len(items) <= limit {
		return items, ""
	}
	items = items[:limit]
	return items, key(items[len(items)-1])
}

func formatNullTime(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339Nano)
}
