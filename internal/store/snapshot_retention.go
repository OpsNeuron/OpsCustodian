package store

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const pruneSnapshotsSQL = `WITH ranked AS (
    SELECT repository_id, id, ingested_at,
           row_number() OVER (PARTITION BY repository_id ORDER BY ingested_at DESC, id DESC) AS ordinal
    FROM snapshots
    WHERE organization_id = $1
), expired AS (
    SELECT repository_id, id
    FROM ranked
    WHERE ingested_at < $2 AND ordinal > $3
    ORDER BY ingested_at, repository_id, id
    LIMIT $4
)
DELETE FROM snapshots AS snapshot
USING expired
WHERE snapshot.organization_id = $1
  AND snapshot.repository_id = expired.repository_id
  AND snapshot.id = expired.id`

func (postgres *Postgres) PruneSnapshots(ctx context.Context, before time.Time, minimumPerRepository, limit int) (int64, error) {
	if err := validateSnapshotRetention(ctx, before, minimumPerRepository, limit); err != nil {
		return 0, err
	}
	transaction, err := postgres.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin snapshot retention transaction: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, pruneSnapshotsSQL, postgres.organizationID, before.UTC(), minimumPerRepository, limit)
	if err != nil {
		return 0, fmt.Errorf("prune snapshots: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count pruned snapshots: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit snapshot retention: %w", err)
	}
	return deleted, nil
}

func (memory *Memory) PruneSnapshots(ctx context.Context, before time.Time, minimumPerRepository, limit int) (int64, error) {
	if err := validateSnapshotRetention(ctx, before, minimumPerRepository, limit); err != nil {
		return 0, err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	type candidate struct {
		repositoryID string
		snapshotID   string
		ingestedAt   time.Time
	}
	candidates := make([]candidate, 0)
	for repositoryID, repository := range memory.repositories {
		snapshots := make([]struct {
			id     string
			stored memorySnapshot
		}, 0, len(repository.snapshots))
		for id, stored := range repository.snapshots {
			snapshots = append(snapshots, struct {
				id     string
				stored memorySnapshot
			}{id: id, stored: stored})
		}
		sort.Slice(snapshots, func(i, j int) bool {
			if snapshots[i].stored.ingestedAt.Equal(snapshots[j].stored.ingestedAt) {
				return snapshots[i].id > snapshots[j].id
			}
			return snapshots[i].stored.ingestedAt.After(snapshots[j].stored.ingestedAt)
		})
		for ordinal, snapshot := range snapshots {
			if ordinal >= minimumPerRepository && snapshot.stored.ingestedAt.Before(before) {
				candidates = append(candidates, candidate{repositoryID: repositoryID, snapshotID: snapshot.id, ingestedAt: snapshot.stored.ingestedAt})
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ingestedAt.Equal(candidates[j].ingestedAt) {
			return candidates[i].repositoryID+"\x00"+candidates[i].snapshotID < candidates[j].repositoryID+"\x00"+candidates[j].snapshotID
		}
		return candidates[i].ingestedAt.Before(candidates[j].ingestedAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for _, candidate := range candidates {
		delete(memory.repositories[candidate.repositoryID].snapshots, candidate.snapshotID)
	}
	return int64(len(candidates)), nil
}

func validateSnapshotRetention(ctx context.Context, before time.Time, minimumPerRepository, limit int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if before.IsZero() || minimumPerRepository < 1 || minimumPerRepository > 1000 || limit < 1 || limit > 10000 {
		return fmt.Errorf("snapshot retention cutoff, minimum, or batch limit is invalid")
	}
	return nil
}
