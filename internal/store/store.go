package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

var ErrNotFound = errors.New("snapshot not found")

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
}

type Writer interface {
	PutSnapshot(context.Context, model.AgentBOM) (Snapshot, error)
}

type Memory struct {
	mu           sync.RWMutex
	repositories map[string]*memoryRepository
}

type memoryRepository struct {
	source    string
	snapshots map[string]model.AgentBOM
	latest    string
}

func NewMemory() *Memory {
	return &Memory{repositories: map[string]*memoryRepository{}}
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
		repository = &memoryRepository{source: cloned.Metadata.Source, snapshots: map[string]model.AgentBOM{}}
		memory.repositories[id] = repository
	}
	repository.snapshots[snapshotID] = cloned
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
		latest := repository.snapshots[repository.latest]
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
	bom := repository.snapshots[snapshotID]
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
	bom, exists := repository.snapshots[snapshotID]
	memory.mu.RUnlock()
	if !exists {
		return Snapshot{}, ErrNotFound
	}
	cloned, err := cloneBOM(bom)
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
	for id, bom := range repository.snapshots {
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
		bom := repository.snapshots[repository.latest]
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

func snapshotSortKey(value SnapshotSummary) string {
	return value.GeneratedAt + "\x00" + value.ID
}

func findingSortKey(value FindingRecord) string {
	return value.RepositoryID + "\x00" + value.Finding.ID
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
