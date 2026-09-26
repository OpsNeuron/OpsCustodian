package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestMemorySnapshotRetentionPreservesMinimumAndBoundsDeletion(t *testing.T) {
	memory := NewMemory()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	repositoryID := ""
	for index := 0; index < 5; index++ {
		bom := model.AgentBOM{
			APIVersion: "opscustodian.dev/v1alpha1",
			Kind:       "AgentBOM",
			Metadata: model.DocumentMetadata{
				Source: "github:acme/platform", Revision: fmt.Sprintf("revision-%d", index),
				Generator: "snapshot-retention-test", NormalizationVersion: "v1alpha1",
			},
			Assets: []model.Asset{},
		}
		snapshot, err := memory.PutSnapshot(context.Background(), bom)
		if err != nil {
			t.Fatal(err)
		}
		repositoryID = snapshot.RepositoryID
		memory.mu.Lock()
		stored := memory.repositories[repositoryID].snapshots[snapshot.SnapshotID]
		stored.ingestedAt = now.Add(time.Duration(index-5) * 24 * time.Hour)
		memory.repositories[repositoryID].snapshots[snapshot.SnapshotID] = stored
		memory.mu.Unlock()
	}

	deleted, err := memory.PruneSnapshots(context.Background(), now.Add(-24*time.Hour), 2, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first prune = %d, %v", deleted, err)
	}
	deleted, err = memory.PruneSnapshots(context.Background(), now.Add(-24*time.Hour), 2, 10)
	if err != nil || deleted != 2 {
		t.Fatalf("second prune = %d, %v", deleted, err)
	}
	page, err := memory.ListSnapshots(context.Background(), repositoryID, PageRequest{Limit: 10})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("retained snapshots = %#v, %v", page, err)
	}
	latest, err := memory.LatestSnapshot(context.Background(), repositoryID)
	if err != nil || latest.BOM.Metadata.Revision != "revision-4" {
		t.Fatalf("latest snapshot = %#v, %v", latest, err)
	}
}

func TestMemorySnapshotRetentionRejectsUnsafeBounds(t *testing.T) {
	memory := NewMemory()
	if _, err := memory.PruneSnapshots(context.Background(), time.Now(), 0, 1); err == nil {
		t.Fatal("expected zero minimum to be rejected")
	}
	if _, err := memory.PruneSnapshots(context.Background(), time.Now(), 1, 10001); err == nil {
		t.Fatal("expected oversized batch to be rejected")
	}
}
