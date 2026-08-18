package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestMemoryStoresRepositoryHistoryAndReturnsLatestSnapshot(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()
	first := testBOM("github:acme/platform", "a1", "medium")
	second := testBOM("github:acme/platform", "a2", "critical")
	other := testBOM("github:acme/other", "b1", "high")
	for _, bom := range []model.AgentBOM{first, second, other} {
		if _, err := memory.PutSnapshot(ctx, bom); err != nil {
			t.Fatalf("PutSnapshot(): %v", err)
		}
	}

	page, err := memory.ListRepositories(ctx, PageRequest{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("ListRepositories() = %#v, %v", page, err)
	}
	id := RepositoryID("github:acme/platform")
	var platform RepositorySummary
	for _, repository := range page.Items {
		if repository.ID == id {
			platform = repository
		}
	}
	if platform.LatestRevision != "a2" || platform.SnapshotCount != 2 || platform.FindingCount != 1 {
		t.Fatalf("unexpected repository summary: %#v", platform)
	}
	snapshot, err := memory.LatestSnapshot(ctx, id)
	if err != nil || snapshot.BOM.Metadata.Revision != "a2" {
		t.Fatalf("LatestSnapshot() = %#v, %v", snapshot, err)
	}

	// Returned values cannot mutate persisted snapshots.
	snapshot.BOM.Metadata.Revision = "tampered"
	repeated, _ := memory.LatestSnapshot(ctx, id)
	if repeated.BOM.Metadata.Revision != "a2" {
		t.Fatal("caller mutated the persisted snapshot")
	}
	history, err := memory.ListSnapshots(ctx, id, PageRequest{Limit: 1})
	if err != nil || len(history.Items) != 1 || history.NextCursor == "" {
		t.Fatalf("first history page = %#v, %v", history, err)
	}
	next, err := memory.ListSnapshots(ctx, id, PageRequest{Limit: 1, Cursor: history.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == history.Items[0].ID {
		t.Fatalf("second history page = %#v, %v", next, err)
	}
	stored, err := memory.Snapshot(ctx, id, next.Items[0].ID)
	if err != nil || stored.SnapshotID != next.Items[0].ID {
		t.Fatalf("Snapshot() = %#v, %v", stored, err)
	}
}

func TestMemoryFiltersFindingsDeterministically(t *testing.T) {
	memory := NewMemory()
	ctx := context.Background()
	for _, bom := range []model.AgentBOM{
		testBOM("github:acme/z", "z1", "critical"),
		testBOM("github:acme/a", "a1", "critical"),
		testBOM("github:acme/m", "m1", "high"),
	} {
		if _, err := memory.PutSnapshot(ctx, bom); err != nil {
			t.Fatal(err)
		}
	}
	page, err := memory.ListFindings(ctx, FindingFilter{Severity: "critical", Page: PageRequest{Limit: 1}})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("ListFindings() = %#v, %v", page, err)
	}
	next, err := memory.ListFindings(ctx, FindingFilter{Severity: "critical", Page: PageRequest{Limit: 1, Cursor: page.NextCursor}})
	if err != nil || len(next.Items) != 1 {
		t.Fatalf("second findings page = %#v, %v", next, err)
	}
	ids := []string{page.Items[0].RepositoryID, next.Items[0].RepositoryID}
	expected := append([]string(nil), ids...)
	if expected[0] > expected[1] {
		expected[0], expected[1] = expected[1], expected[0]
	}
	if !reflect.DeepEqual(ids, expected) {
		t.Fatalf("findings are not deterministic: %#v", ids)
	}
}

func TestMemoryRejectsInvalidInputAndHonorsContext(t *testing.T) {
	memory := NewMemory()
	if _, err := memory.PutSnapshot(context.Background(), model.AgentBOM{}); err == nil {
		t.Fatal("invalid BOM was accepted")
	}
	if _, err := memory.LatestSnapshot(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing snapshot error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := memory.ListRepositories(cancelled, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}

func testBOM(source, revision, severity string) model.AgentBOM {
	asset := model.Asset{
		ID: "agent:" + revision, Type: "agent", Name: "agent", Source: model.Source{Path: "AGENTS.md"},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "evidence", Path: "AGENTS.md", Parser: "test", Confidence: "high"}},
	}
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: source, Revision: revision, NormalizationVersion: "v1alpha1"},
		Assets:   []model.Asset{asset},
		Findings: []model.Finding{{
			ID: "finding-" + revision, Type: "test-finding", Severity: severity, AssetID: asset.ID,
			Title: "Test finding", Reason: "Test risk.", RemediationID: "test.fix", Remediation: "Fix it.",
			Evidence: []model.FindingEvidence{{AssetID: asset.ID, EvidenceID: "evidence"}},
		}},
	}
}
