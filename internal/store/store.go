package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

var (
	ErrNotFound  = errors.New("snapshot not found")
	ErrConflict  = errors.New("immutable snapshot conflict")
	ErrLeaseLost = errors.New("scheduler lease lost")
)

type RepositorySummary struct {
	ID             string `json:"id"`
	Source         string `json:"source"`
	LatestRevision string `json:"latestRevision"`
	SnapshotCount  int    `json:"snapshotCount"`
	AssetCount     int    `json:"assetCount"`
	FindingCount   int    `json:"findingCount"`
}

type Snapshot struct {
	RepositoryID string         `json:"repositoryId"`
	SnapshotID   string         `json:"snapshotId"`
	BOM          model.AgentBOM `json:"bom"`
}

type SnapshotSummary struct {
	ID           string `json:"id"`
	RepositoryID string `json:"repositoryId"`
	Revision     string `json:"revision"`
	GeneratedAt  string `json:"generatedAt,omitempty"`
	AssetCount   int    `json:"assetCount"`
	FindingCount int    `json:"findingCount"`
}

type PageRequest struct {
	Limit  int
	Cursor string
}

type RepositoryPage struct {
	Items      []RepositorySummary
	NextCursor string
}

type SnapshotPage struct {
	Items      []SnapshotSummary
	NextCursor string
}

type FindingPage struct {
	Items      []FindingRecord
	NextCursor string
}

type FindingLifecycleRecord struct {
	RepositoryID     string        `json:"repositoryId"`
	Source           string        `json:"source"`
	FindingID        string        `json:"findingId"`
	Status           string        `json:"status"`
	FirstRevision    string        `json:"firstRevision"`
	LastRevision     string        `json:"lastRevision"`
	ResolvedRevision string        `json:"resolvedRevision,omitempty"`
	FirstObservedAt  string        `json:"firstObservedAt,omitempty"`
	LastObservedAt   string        `json:"lastObservedAt,omitempty"`
	ResolvedAt       string        `json:"resolvedAt,omitempty"`
	Occurrences      int           `json:"occurrences"`
	Finding          model.Finding `json:"finding"`
}

type FindingLifecycleFilter struct {
	RepositoryID string
	Severity     string
	Status       string
	Page         PageRequest
}

type FindingLifecyclePage struct {
	Items      []FindingLifecycleRecord
	NextCursor string
}

type FindingRecord struct {
	RepositoryID string        `json:"repositoryId"`
	Source       string        `json:"source"`
	Revision     string        `json:"revision"`
	Finding      model.Finding `json:"finding"`
}

type FindingFilter struct {
	RepositoryID string
	Severity     string
	Page         PageRequest
}

type Reader interface {
	ListRepositories(context.Context, PageRequest) (RepositoryPage, error)
	LatestSnapshot(context.Context, string) (Snapshot, error)
	Snapshot(context.Context, string, string) (Snapshot, error)
	ListSnapshots(context.Context, string, PageRequest) (SnapshotPage, error)
	ListFindings(context.Context, FindingFilter) (FindingPage, error)
	ListFindingLifecycle(context.Context, FindingLifecycleFilter) (FindingLifecyclePage, error)
}

type Writer interface {
	PutSnapshot(context.Context, model.AgentBOM) (Snapshot, error)
}

type FencedWriter interface {
	PutSnapshotWithLease(context.Context, model.AgentBOM, SchedulerLease) (Snapshot, error)
}

type Memory struct {
	mu           sync.RWMutex
	repositories map[string]*memoryRepository
	leases       map[string]SchedulerLease
	nextFence    map[string]int64
}

type memoryRepository struct {
	source       string
	snapshots    map[string]memorySnapshot
	latest       string
	nextSequence uint64
}

type memorySnapshot struct {
	bom      model.AgentBOM
	sequence uint64
}

func NewMemory() *Memory {
	return &Memory{repositories: map[string]*memoryRepository{}, leases: map[string]SchedulerLease{}, nextFence: map[string]int64{}}
}

var _ SchedulerLeaseStore = (*Memory)(nil)

func (memory *Memory) AcquireSchedulerLease(ctx context.Context, name, holderID string, ttl time.Duration) (SchedulerLease, bool, error) {
	if err := validateSchedulerLeaseInput(ctx, name, holderID, ttl); err != nil {
		return SchedulerLease{}, false, err
	}
	now := time.Now().UTC()
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.leases[name]
	if exists && current.ExpiresAt.After(now) && current.HolderID != holderID {
		return SchedulerLease{}, false, nil
	}
	token := current.FencingToken
	if !exists || current.HolderID != holderID || !current.ExpiresAt.After(now) {
		memory.nextFence[name]++
		token = memory.nextFence[name]
	}
	lease := SchedulerLease{Name: name, HolderID: holderID, FencingToken: token, ExpiresAt: now.Add(ttl)}
	memory.leases[name] = lease
	return lease, true, nil
}

func (memory *Memory) RenewSchedulerLease(ctx context.Context, lease SchedulerLease, ttl time.Duration) (SchedulerLease, bool, error) {
	if lease.FencingToken <= 0 {
		return SchedulerLease{}, false, fmt.Errorf("scheduler lease fencing token must be positive")
	}
	if err := validateSchedulerLeaseInput(ctx, lease.Name, lease.HolderID, ttl); err != nil {
		return SchedulerLease{}, false, err
	}
	now := time.Now().UTC()
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.leases[lease.Name]
	if !exists || current.HolderID != lease.HolderID || current.FencingToken != lease.FencingToken || !current.ExpiresAt.After(now) {
		return SchedulerLease{}, false, nil
	}
	current.ExpiresAt = now.Add(ttl)
	memory.leases[lease.Name] = current
	return current, true, nil
}

func (memory *Memory) ReleaseSchedulerLease(ctx context.Context, lease SchedulerLease) (bool, error) {
	if lease.FencingToken <= 0 {
		return false, fmt.Errorf("scheduler lease fencing token must be positive")
	}
	if err := validateSchedulerLeaseIdentity(ctx, lease.Name, lease.HolderID); err != nil {
		return false, err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.leases[lease.Name]
	if !exists || current.HolderID != lease.HolderID || current.FencingToken != lease.FencingToken {
		return false, nil
	}
	current.ExpiresAt = time.Now().UTC()
	memory.leases[lease.Name] = current
	return true, nil
}

func RepositoryID(source string) string {
	sum := sha256.Sum256([]byte(source))
	return fmt.Sprintf("repository-%x", sum[:8])
}

func SnapshotID(repositoryID, revision string) string {
	sum := sha256.Sum256([]byte(repositoryID + "\x00" + revision))
	return fmt.Sprintf("snapshot-%x", sum[:8])
}

func (memory *Memory) PutSnapshot(ctx context.Context, bom model.AgentBOM) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return Snapshot{}, fmt.Errorf("invalid Agent BOM: %s at %s", issues[0].Code, issues[0].Path)
	}
	cloned, err := cloneBOM(bom)
	if err != nil {
		return Snapshot{}, err
	}
	id := RepositoryID(cloned.Metadata.Source)
	snapshotID := SnapshotID(id, cloned.Metadata.Revision)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	repository := memory.repositories[id]
	if repository == nil {
		repository = &memoryRepository{source: cloned.Metadata.Source, snapshots: map[string]memorySnapshot{}}
		memory.repositories[id] = repository
	}
	stored, exists := repository.snapshots[snapshotID]
	if exists {
		existing, _ := json.Marshal(stored.bom)
		proposed, _ := json.Marshal(cloned)
		if string(existing) != string(proposed) {
			return Snapshot{}, fmt.Errorf("%w: snapshot %s", ErrConflict, snapshotID)
		}
	}
	if !exists {
		repository.nextSequence++
		stored.sequence = repository.nextSequence
	}
	stored.bom = cloned
	repository.snapshots[snapshotID] = stored
	repository.latest = snapshotID
	return Snapshot{RepositoryID: id, SnapshotID: snapshotID, BOM: cloned}, nil
}

func (memory *Memory) ListRepositories(ctx context.Context, page PageRequest) (RepositoryPage, error) {
	if err := ctx.Err(); err != nil {
		return RepositoryPage{}, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	result := make([]RepositorySummary, 0, len(memory.repositories))
	for id, repository := range memory.repositories {
		latest := repository.snapshots[repository.latest].bom
		result = append(result, RepositorySummary{
			ID: id, Source: repository.source, LatestRevision: latest.Metadata.Revision,
			SnapshotCount: len(repository.snapshots), AssetCount: len(latest.Assets), FindingCount: len(latest.Findings),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	items, next := pageSlice(result, page, func(value RepositorySummary) string { return value.ID })
	return RepositoryPage{Items: items, NextCursor: next}, nil
}

func (memory *Memory) LatestSnapshot(ctx context.Context, repositoryID string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	memory.mu.RLock()
	repository := memory.repositories[repositoryID]
	if repository == nil {
		memory.mu.RUnlock()
		return Snapshot{}, ErrNotFound
	}
	snapshotID := repository.latest
	bom := repository.snapshots[snapshotID].bom
	memory.mu.RUnlock()
	cloned, err := cloneBOM(bom)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{RepositoryID: repositoryID, SnapshotID: snapshotID, BOM: cloned}, nil
}

func (memory *Memory) Snapshot(ctx context.Context, repositoryID, snapshotID string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	memory.mu.RLock()
	repository := memory.repositories[repositoryID]
	if repository == nil {
		memory.mu.RUnlock()
		return Snapshot{}, ErrNotFound
	}
	stored, exists := repository.snapshots[snapshotID]
	memory.mu.RUnlock()
	if !exists {
		return Snapshot{}, ErrNotFound
	}
	cloned, err := cloneBOM(stored.bom)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{RepositoryID: repositoryID, SnapshotID: snapshotID, BOM: cloned}, nil
}

func (memory *Memory) ListSnapshots(ctx context.Context, repositoryID string, page PageRequest) (SnapshotPage, error) {
	if err := ctx.Err(); err != nil {
		return SnapshotPage{}, err
	}
	memory.mu.RLock()
	repository := memory.repositories[repositoryID]
	if repository == nil {
		memory.mu.RUnlock()
		return SnapshotPage{}, ErrNotFound
	}
	result := make([]SnapshotSummary, 0, len(repository.snapshots))
	for id, stored := range repository.snapshots {
		bom := stored.bom
		result = append(result, SnapshotSummary{
			ID: id, RepositoryID: repositoryID, Revision: bom.Metadata.Revision, GeneratedAt: bom.Metadata.GeneratedAt,
			AssetCount: len(bom.Assets), FindingCount: len(bom.Findings),
		})
	}
	memory.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return snapshotSortKey(result[i]) < snapshotSortKey(result[j]) })
	items, next := pageSlice(result, page, snapshotSortKey)
	return SnapshotPage{Items: items, NextCursor: next}, nil
}

func (memory *Memory) ListFindings(ctx context.Context, filter FindingFilter) (FindingPage, error) {
	if err := ctx.Err(); err != nil {
		return FindingPage{}, err
	}
	memory.mu.RLock()
	result := make([]FindingRecord, 0)
	for id, repository := range memory.repositories {
		if filter.RepositoryID != "" && filter.RepositoryID != id {
			continue
		}
		bom := repository.snapshots[repository.latest].bom
		for _, finding := range bom.Findings {
			if filter.Severity != "" && filter.Severity != finding.Severity {
				continue
			}
			result = append(result, FindingRecord{RepositoryID: id, Source: repository.source, Revision: bom.Metadata.Revision, Finding: finding})
		}
	}
	memory.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return result[i].RepositoryID+"\x00"+result[i].Finding.ID < result[j].RepositoryID+"\x00"+result[j].Finding.ID
	})
	items, next := pageSlice(result, filter.Page, findingSortKey)
	return FindingPage{Items: items, NextCursor: next}, nil
}

func (memory *Memory) ListFindingLifecycle(ctx context.Context, filter FindingLifecycleFilter) (FindingLifecyclePage, error) {
	if err := ctx.Err(); err != nil {
		return FindingLifecyclePage{}, err
	}
	memory.mu.RLock()
	result := make([]FindingLifecycleRecord, 0)
	for repositoryID, repository := range memory.repositories {
		if filter.RepositoryID != "" && filter.RepositoryID != repositoryID {
			continue
		}
		snapshots := make([]memorySnapshot, 0, len(repository.snapshots))
		for _, snapshot := range repository.snapshots {
			snapshots = append(snapshots, snapshot)
		}
		sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].sequence < snapshots[j].sequence })
		states := lifecycleStates(repositoryID, repository.source, snapshots)
		for _, state := range states {
			if filter.Status != "" && filter.Status != state.Status {
				continue
			}
			if filter.Severity != "" && filter.Severity != state.Finding.Severity {
				continue
			}
			result = append(result, state)
		}
	}
	memory.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return lifecycleSortKey(result[i]) < lifecycleSortKey(result[j]) })
	items, next := pageSlice(result, filter.Page, lifecycleSortKey)
	return FindingLifecyclePage{Items: items, NextCursor: next}, nil
}

type lifecycleState struct {
	record FindingLifecycleRecord
	active bool
}

func lifecycleStates(repositoryID, source string, snapshots []memorySnapshot) []FindingLifecycleRecord {
	states := map[string]lifecycleState{}
	for _, snapshot := range snapshots {
		present := map[string]model.Finding{}
		for _, finding := range snapshot.bom.Findings {
			present[finding.ID] = finding
			state, exists := states[finding.ID]
			if !exists || !state.active {
				state = lifecycleState{active: true, record: FindingLifecycleRecord{
					RepositoryID: repositoryID, Source: source, FindingID: finding.ID, Status: "introduced",
					FirstRevision: snapshot.bom.Metadata.Revision, LastRevision: snapshot.bom.Metadata.Revision,
					FirstObservedAt: snapshot.bom.Metadata.GeneratedAt, LastObservedAt: snapshot.bom.Metadata.GeneratedAt,
					Occurrences: 1, Finding: finding,
				}}
			} else {
				state.record.Status = "persisting"
				state.record.LastRevision = snapshot.bom.Metadata.Revision
				state.record.LastObservedAt = snapshot.bom.Metadata.GeneratedAt
				state.record.Occurrences++
				state.record.Finding = finding
			}
			states[finding.ID] = state
		}
		for findingID, state := range states {
			if state.active {
				if _, exists := present[findingID]; !exists {
					state.active = false
					state.record.Status = "resolved"
					state.record.ResolvedRevision = snapshot.bom.Metadata.Revision
					state.record.ResolvedAt = snapshot.bom.Metadata.GeneratedAt
					states[findingID] = state
				}
			}
		}
	}
	result := make([]FindingLifecycleRecord, 0, len(states))
	for _, state := range states {
		result = append(result, state.record)
	}
	return result
}

func snapshotSortKey(value SnapshotSummary) string {
	return value.GeneratedAt + "\x00" + value.ID
}

func findingSortKey(value FindingRecord) string {
	return value.RepositoryID + "\x00" + value.Finding.ID
}

func lifecycleSortKey(value FindingLifecycleRecord) string {
	return value.RepositoryID + "\x00" + value.FindingID
}

func pageSlice[T any](values []T, page PageRequest, key func(T) string) ([]T, string) {
	start := 0
	if page.Cursor != "" {
		start = sort.Search(len(values), func(index int) bool { return key(values[index]) > page.Cursor })
	}
	limit := page.Limit
	if limit <= 0 || limit > len(values)-start {
		limit = len(values) - start
	}
	end := start + limit
	items := append([]T(nil), values[start:end]...)
	next := ""
	if end < len(values) && len(items) > 0 {
		next = key(items[len(items)-1])
	}
	return items, next
}

func cloneBOM(value model.AgentBOM) (model.AgentBOM, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return model.AgentBOM{}, fmt.Errorf("copy Agent BOM: %w", err)
	}
	var result model.AgentBOM
	if err := json.Unmarshal(content, &result); err != nil {
		return model.AgentBOM{}, fmt.Errorf("copy Agent BOM: %w", err)
	}
	return result, nil
}
