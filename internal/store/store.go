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
	BOM          model.AgentBOM `json:"bom"`
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
}

type Reader interface {
	ListRepositories(context.Context) ([]RepositorySummary, error)
	LatestSnapshot(context.Context, string) (Snapshot, error)
	ListFindings(context.Context, FindingFilter) ([]FindingRecord, error)
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
	revisions map[string]model.AgentBOM
	latest    string
}

func NewMemory() *Memory {
	return &Memory{repositories: map[string]*memoryRepository{}}
}

func RepositoryID(source string) string {
	sum := sha256.Sum256([]byte(source))
	return fmt.Sprintf("repository-%x", sum[:8])
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
	memory.mu.Lock()
	defer memory.mu.Unlock()
	repository := memory.repositories[id]
	if repository == nil {
		repository = &memoryRepository{source: cloned.Metadata.Source, revisions: map[string]model.AgentBOM{}}
		memory.repositories[id] = repository
	}
	repository.revisions[cloned.Metadata.Revision] = cloned
	repository.latest = cloned.Metadata.Revision
	return Snapshot{RepositoryID: id, BOM: cloned}, nil
}

func (memory *Memory) ListRepositories(ctx context.Context) ([]RepositorySummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	result := make([]RepositorySummary, 0, len(memory.repositories))
	for id, repository := range memory.repositories {
		latest := repository.revisions[repository.latest]
		result = append(result, RepositorySummary{
			ID: id, Source: repository.source, LatestRevision: repository.latest,
			SnapshotCount: len(repository.revisions), AssetCount: len(latest.Assets), FindingCount: len(latest.Findings),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
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
	bom := repository.revisions[repository.latest]
	memory.mu.RUnlock()
	cloned, err := cloneBOM(bom)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{RepositoryID: repositoryID, BOM: cloned}, nil
}

func (memory *Memory) ListFindings(ctx context.Context, filter FindingFilter) ([]FindingRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory.mu.RLock()
	result := make([]FindingRecord, 0)
	for id, repository := range memory.repositories {
		if filter.RepositoryID != "" && filter.RepositoryID != id {
			continue
		}
		bom := repository.revisions[repository.latest]
		for _, finding := range bom.Findings {
			if filter.Severity != "" && filter.Severity != finding.Severity {
				continue
			}
			result = append(result, FindingRecord{RepositoryID: id, Source: repository.source, Revision: repository.latest, Finding: finding})
		}
	}
	memory.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return result[i].RepositoryID+"\x00"+result[i].Finding.ID < result[j].RepositoryID+"\x00"+result[j].Finding.ID
	})
	return result, nil
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
