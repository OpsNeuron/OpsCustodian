package ingestion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/store"
)

const (
	StatusPersisted = "persisted"
	StatusUnchanged = "unchanged"
	StatusConflict  = "conflict"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

type Repository struct {
	Source string
}

type FetchRequest struct {
	Source        string
	KnownRevision string
}

type FetchResult struct {
	BOM       model.AgentBOM
	Unchanged bool
}

type Fetcher interface {
	Fetch(context.Context, FetchRequest) (FetchResult, error)
}

type Result struct {
	Source   string
	Status   string
	Snapshot store.Snapshot
	Err      error
}

type Orchestrator struct {
	Reader         store.Reader
	Writer         store.Writer
	Fetcher        Fetcher
	MaxConcurrency int
}

func (orchestrator Orchestrator) Run(ctx context.Context, repositories []Repository) ([]Result, error) {
	if orchestrator.Reader == nil || orchestrator.Writer == nil || orchestrator.Fetcher == nil {
		return nil, fmt.Errorf("ingestion reader, writer, and fetcher are required")
	}
	if orchestrator.MaxConcurrency < 1 {
		return nil, fmt.Errorf("ingestion concurrency must be positive")
	}
	seen := make(map[string]struct{}, len(repositories))
	results := make([]Result, len(repositories))
	for index, repository := range repositories {
		repository.Source = strings.TrimSpace(repository.Source)
		if repository.Source == "" {
			return nil, fmt.Errorf("repository source at index %d is required", index)
		}
		if _, exists := seen[repository.Source]; exists {
			return nil, fmt.Errorf("duplicate repository source %q", repository.Source)
		}
		seen[repository.Source] = struct{}{}
		repositories[index] = repository
		results[index] = Result{Source: repository.Source, Status: StatusCancelled, Err: context.Canceled}
	}

	semaphore := make(chan struct{}, orchestrator.MaxConcurrency)
	var workers sync.WaitGroup
	for index, repository := range repositories {
		if ctx.Err() != nil {
			break
		}
		workers.Add(1)
		go func(index int, repository Repository) {
			defer workers.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[index].Err = ctx.Err()
				return
			}
			results[index] = orchestrator.ingest(ctx, repository)
		}(index, repository)
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func (orchestrator Orchestrator) ingest(ctx context.Context, repository Repository) Result {
	result := Result{Source: repository.Source, Status: StatusFailed}
	repositoryID := store.RepositoryID(repository.Source)
	knownRevision := ""
	latest, err := orchestrator.Reader.LatestSnapshot(ctx, repositoryID)
	if err == nil {
		knownRevision = latest.BOM.Metadata.Revision
	} else if !errors.Is(err, store.ErrNotFound) {
		result.Err = fmt.Errorf("read latest snapshot: %w", err)
		return result
	}

	fetched, err := orchestrator.Fetcher.Fetch(ctx, FetchRequest{Source: repository.Source, KnownRevision: knownRevision})
	if err != nil {
		result.Err = fmt.Errorf("fetch repository: %w", err)
		return result
	}
	if fetched.Unchanged {
		if knownRevision == "" {
			result.Err = fmt.Errorf("fetcher reported unchanged repository without a known snapshot")
			return result
		}
		result.Status = StatusUnchanged
		result.Snapshot = latest
		result.Err = nil
		return result
	}
	if fetched.BOM.Metadata.Source != repository.Source {
		result.Err = fmt.Errorf("fetched Agent BOM source does not match configured repository")
		return result
	}
	snapshot, err := orchestrator.Writer.PutSnapshot(ctx, fetched.BOM)
	if errors.Is(err, store.ErrConflict) {
		result.Status = StatusConflict
		result.Err = err
		return result
	}
	if err != nil {
		result.Err = fmt.Errorf("persist snapshot: %w", err)
		return result
	}
	result.Status = StatusPersisted
	result.Snapshot = snapshot
	result.Err = nil
	return result
}
