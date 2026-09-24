package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

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

func TestMemoryFiltersRepositoryScopedCollectionsBeforePagination(t *testing.T) {
	memory := NewMemory()
	allowed := testBOM("github:acme/allowed", "one", "critical")
	denied := testBOM("github:acme/denied", "two", "critical")
	for _, bom := range []model.AgentBOM{allowed, denied} {
		if _, err := memory.PutSnapshot(context.Background(), bom); err != nil {
			t.Fatal(err)
		}
	}
	allowedID := RepositoryID(allowed.Metadata.Source)
	repositories, err := memory.ListRepositories(context.Background(), PageRequest{Limit: 1, RepositoryIDs: []string{allowedID}})
	if err != nil || len(repositories.Items) != 1 || repositories.Items[0].ID != allowedID || repositories.NextCursor != "" {
		t.Fatalf("repository-scoped page = %#v, %v", repositories, err)
	}
	findings, err := memory.ListFindings(context.Background(), FindingFilter{RepositoryIDs: []string{allowedID}, Page: PageRequest{Limit: 10}})
	if err != nil || len(findings.Items) != 1 || findings.Items[0].RepositoryID != allowedID {
		t.Fatalf("repository-scoped findings = %#v, %v", findings, err)
	}
	lifecycles, err := memory.ListFindingLifecycle(context.Background(), FindingLifecycleFilter{RepositoryIDs: []string{allowedID}, Page: PageRequest{Limit: 10}})
	if err != nil || len(lifecycles.Items) != 1 || lifecycles.Items[0].RepositoryID != allowedID {
		t.Fatalf("repository-scoped lifecycles = %#v, %v", lifecycles, err)
	}
}

func TestMemoryComputesFindingLifecycleEpisodes(t *testing.T) {
	memory := NewMemory()
	ctx := context.Background()
	snapshots := []model.AgentBOM{
		lifecycleBOM("r1", "2026-08-18T01:00:00Z", "finding-resolved"),
		lifecycleBOM("r2", "2026-08-18T02:00:00Z", "finding-resolved", "finding-persisting"),
		lifecycleBOM("r3", "2026-08-18T03:00:00Z", "finding-persisting"),
		lifecycleBOM("r4", "2026-08-18T04:00:00Z", "finding-persisting", "finding-introduced"),
	}
	for _, bom := range snapshots {
		if _, err := memory.PutSnapshot(ctx, bom); err != nil {
			t.Fatal(err)
		}
	}
	page, err := memory.ListFindingLifecycle(ctx, FindingLifecycleFilter{RepositoryID: RepositoryID("github:acme/lifecycle"), Page: PageRequest{Limit: 10}})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("ListFindingLifecycle() = %#v, %v", page, err)
	}
	byID := map[string]FindingLifecycleRecord{}
	for _, record := range page.Items {
		byID[record.FindingID] = record
	}
	if value := byID["finding-resolved"]; value.Status != "resolved" || value.Occurrences != 2 || value.ResolvedRevision != "r3" || value.ResolvedAt != "2026-08-18T03:00:00Z" {
		t.Errorf("unexpected resolved lifecycle: %#v", value)
	}
	if value := byID["finding-persisting"]; value.Status != "persisting" || value.Occurrences != 3 || value.FirstRevision != "r2" || value.LastRevision != "r4" {
		t.Errorf("unexpected persisting lifecycle: %#v", value)
	}
	if value := byID["finding-introduced"]; value.Status != "introduced" || value.Occurrences != 1 || value.FirstObservedAt != "2026-08-18T04:00:00Z" {
		t.Errorf("unexpected introduced lifecycle: %#v", value)
	}
	resolved, err := memory.ListFindingLifecycle(ctx, FindingLifecycleFilter{Status: "resolved", Page: PageRequest{Limit: 1}})
	if err != nil || len(resolved.Items) != 1 || resolved.Items[0].FindingID != "finding-resolved" {
		t.Fatalf("resolved lifecycle filter = %#v, %v", resolved, err)
	}
}

func TestMemoryStartsNewLifecycleEpisodeAfterReintroduction(t *testing.T) {
	memory := NewMemory()
	ctx := context.Background()
	for _, bom := range []model.AgentBOM{
		lifecycleBOM("r1", "2026-08-18T01:00:00Z", "finding-returned"),
		lifecycleBOM("r2", "2026-08-18T02:00:00Z"),
		lifecycleBOM("r3", "2026-08-18T03:00:00Z", "finding-returned"),
	} {
		if _, err := memory.PutSnapshot(ctx, bom); err != nil {
			t.Fatal(err)
		}
	}
	page, err := memory.ListFindingLifecycle(ctx, FindingLifecycleFilter{Page: PageRequest{Limit: 10}})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListFindingLifecycle() = %#v, %v", page, err)
	}
	value := page.Items[0]
	if value.Status != "introduced" || value.Occurrences != 1 || value.FirstRevision != "r3" || value.FirstObservedAt != "2026-08-18T03:00:00Z" || value.ResolvedAt != "" {
		t.Fatalf("reintroduced finding did not start a new episode: %#v", value)
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

func TestMemorySchedulerLeasePreservesFencingAcrossRelease(t *testing.T) {
	memory := NewMemory()
	ctx := context.Background()
	first, ok, err := memory.AcquireSchedulerLease(ctx, "repository-ingestion", "instance-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first acquire = %#v, %v, %v", first, ok, err)
	}
	if released, err := memory.ReleaseSchedulerLease(ctx, first); err != nil || !released {
		t.Fatalf("release = %v, %v", released, err)
	}
	second, ok, err := memory.AcquireSchedulerLease(ctx, "repository-ingestion", "instance-b", time.Minute)
	if err != nil || !ok || second.FencingToken <= first.FencingToken {
		t.Fatalf("second acquire = %#v, %v, %v; first = %#v", second, ok, err, first)
	}
	if _, ok, err := memory.RenewSchedulerLease(ctx, first, time.Minute); err != nil || ok {
		t.Fatalf("stale renewal = %v, %v", ok, err)
	}
}

func lifecycleBOM(revision, generatedAt string, findingIDs ...string) model.AgentBOM {
	asset := model.Asset{
		ID: "agent:stable", Type: "agent", Name: "agent", Source: model.Source{Path: "AGENTS.md"},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "evidence", Path: "AGENTS.md", Parser: "test", Confidence: "high"}},
	}
	findings := make([]model.Finding, 0, len(findingIDs))
	for _, id := range findingIDs {
		findings = append(findings, model.Finding{
			ID: id, Type: "test-finding", Severity: "high", AssetID: asset.ID,
			Title: "Test finding", Reason: "Test risk.", RemediationID: "test.fix", Remediation: "Fix it.",
			Evidence: []model.FindingEvidence{{AssetID: asset.ID, EvidenceID: "evidence"}},
		})
	}
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: "github:acme/lifecycle", Revision: revision, GeneratedAt: generatedAt, NormalizationVersion: "v1alpha1"},
		Assets:   assetSlice(asset), Findings: findings,
	}
}

func assetSlice(asset model.Asset) []model.Asset { return []model.Asset{asset} }
