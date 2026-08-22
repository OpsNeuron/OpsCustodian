package ingestion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

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
	Source      string
	Connector   string
	Location    string
	Revision    string
	Boundaries  []string
	MaxFileSize int64
}

type FetchRequest struct {
	Repository    Repository
	KnownRevision string
}

type FetchResult struct {
	BOM       model.AgentBOM
	Unchanged bool
}

type Fetcher interface {
	Fetch(context.Context, FetchRequest) (FetchResult, error)
}

type transientError struct{ err error }

func (err transientError) Error() string { return err.err.Error() }
func (err transientError) Unwrap() error { return err.err }

// Transient marks connector failures that may safely be retried, such as rate
// limiting or temporary provider unavailability. All unmarked errors are
// permanent by default.
func Transient(err error) error {
	if err == nil {
		return nil
	}
	return transientError{err: err}
}

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type Result struct {
	Source       string
	Status       string
	Snapshot     store.Snapshot
	Err          error
	Attempts     int
	FailureClass string
}

type Orchestrator struct {
	Reader            store.Reader
	Writer            store.Writer
	Fetcher           Fetcher
	MaxConcurrency    int
	RepositoryTimeout time.Duration
	Retry             RetryPolicy
	sleep             func(context.Context, time.Duration) error
}

func (orchestrator Orchestrator) Run(ctx context.Context, repositories []Repository) ([]Result, error) {
	if orchestrator.Reader == nil || orchestrator.Writer == nil || orchestrator.Fetcher == nil {
		return nil, fmt.Errorf("ingestion reader, writer, and fetcher are required")
	}
	if orchestrator.MaxConcurrency < 1 {
		return nil, fmt.Errorf("ingestion concurrency must be positive")
	}
	if orchestrator.RepositoryTimeout < 0 || orchestrator.Retry.MaxAttempts < 0 || orchestrator.Retry.InitialBackoff < 0 || orchestrator.Retry.MaxBackoff < 0 {
		return nil, fmt.Errorf("ingestion timeout and retry values must not be negative")
	}
	if orchestrator.Retry.MaxAttempts > 1 && (orchestrator.Retry.InitialBackoff <= 0 || orchestrator.Retry.MaxBackoff < orchestrator.Retry.InitialBackoff) {
		return nil, fmt.Errorf("retry backoff must be positive and bounded when retries are enabled")
	}
	seen := make(map[string]struct{}, len(repositories))
	normalized := make([]Repository, len(repositories))
	results := make([]Result, len(repositories))
	for index, repository := range repositories {
		repository.Source = strings.TrimSpace(repository.Source)
		repository.Boundaries = append([]string(nil), repository.Boundaries...)
		if repository.Source == "" {
			return nil, fmt.Errorf("repository source at index %d is required", index)
		}
		if _, exists := seen[repository.Source]; exists {
			return nil, fmt.Errorf("duplicate repository source %q", repository.Source)
		}
		seen[repository.Source] = struct{}{}
		normalized[index] = repository
		results[index] = Result{Source: repository.Source, Status: StatusCancelled, Err: context.Canceled}
	}

	semaphore := make(chan struct{}, orchestrator.MaxConcurrency)
	var workers sync.WaitGroup
	for index, repository := range normalized {
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
	if orchestrator.RepositoryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, orchestrator.RepositoryTimeout)
		defer cancel()
	}
	repositoryID := store.RepositoryID(repository.Source)
	knownRevision := ""
	latest, err := orchestrator.Reader.LatestSnapshot(ctx, repositoryID)
	if err == nil {
		knownRevision = latest.BOM.Metadata.Revision
	} else if !errors.Is(err, store.ErrNotFound) {
		result.Err = fmt.Errorf("read latest snapshot: %w", err)
		return result
	}

	fetched, attempts, err := orchestrator.fetchWithRetry(ctx, FetchRequest{Repository: repository, KnownRevision: knownRevision})
	result.Attempts = attempts
	if err != nil {
		result.Err = fmt.Errorf("fetch repository: %w", err)
		if errors.Is(err, context.Canceled) {
			result.Status = StatusCancelled
			result.FailureClass = "cancelled"
		} else if errors.Is(err, context.DeadlineExceeded) {
			result.FailureClass = "timeout"
		} else if isTransient(err) {
			result.FailureClass = "transient"
		} else {
			result.FailureClass = "permanent"
		}
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

func (orchestrator Orchestrator) fetchWithRetry(ctx context.Context, request FetchRequest) (FetchResult, int, error) {
	maxAttempts := orchestrator.Retry.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1
	}
	backoff := orchestrator.Retry.InitialBackoff
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := orchestrator.Fetcher.Fetch(ctx, request)
		if err == nil {
			return result, attempt, nil
		}
		if !isTransient(err) || attempt == maxAttempts || ctx.Err() != nil {
			if ctx.Err() != nil {
				return FetchResult{}, attempt, ctx.Err()
			}
			return FetchResult{}, attempt, err
		}
		if err := orchestrator.wait(ctx, backoff); err != nil {
			return FetchResult{}, attempt, err
		}
		if backoff >= orchestrator.Retry.MaxBackoff-backoff {
			backoff = orchestrator.Retry.MaxBackoff
		} else {
			backoff *= 2
		}
	}
	panic("unreachable")
}

func (orchestrator Orchestrator) wait(ctx context.Context, duration time.Duration) error {
	if orchestrator.sleep != nil {
		return orchestrator.sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isTransient(err error) bool {
	var candidate transientError
	return errors.As(err, &candidate)
}
