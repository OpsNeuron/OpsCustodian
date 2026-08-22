package ingestion

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestOrchestratorBoundsConcurrencyAndPreservesResultOrder(t *testing.T) {
	memory := store.NewMemory()
	fetcher := &concurrencyFetcher{release: make(chan struct{})}
	orchestrator := Orchestrator{Reader: memory, Writer: memory, Fetcher: fetcher, MaxConcurrency: 2}
	repositories := []Repository{{Source: "github:acme/one"}, {Source: "github:acme/two"}, {Source: "github:acme/three"}}
	done := make(chan []Result, 1)
	go func() {
		results, _ := orchestrator.Run(context.Background(), repositories)
		done <- results
	}()
	deadline := time.After(time.Second)
	for fetcher.peak.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("two concurrent fetches did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if current := fetcher.active.Load(); current != 2 {
		t.Fatalf("active fetches = %d", current)
	}
	close(fetcher.release)
	results := <-done
	if fetcher.peak.Load() != 2 {
		t.Fatalf("peak concurrency = %d", fetcher.peak.Load())
	}
	for index, result := range results {
		if result.Source != repositories[index].Source || result.Status != StatusPersisted || result.Err != nil {
			t.Fatalf("result[%d] = %#v", index, result)
		}
	}
}

func TestOrchestratorSuppliesKnownRevisionAndSkipsUnchangedRepository(t *testing.T) {
	memory := store.NewMemory()
	previous := ingestionTestBOM("github:acme/platform", "revision-1")
	snapshot, err := memory.PutSnapshot(context.Background(), previous)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &recordingFetcher{result: FetchResult{Unchanged: true}}
	results, err := (Orchestrator{Reader: memory, Writer: memory, Fetcher: fetcher, MaxConcurrency: 1}).Run(context.Background(), []Repository{{Source: previous.Metadata.Source}})
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.requests[0].KnownRevision != "revision-1" || results[0].Status != StatusUnchanged || results[0].Snapshot.SnapshotID != snapshot.SnapshotID {
		t.Fatalf("request = %#v, result = %#v", fetcher.requests[0], results[0])
	}
}

func TestOrchestratorIsolatesConflictsAndRejectsCrossRepositoryBOM(t *testing.T) {
	memory := store.NewMemory()
	existing := ingestionTestBOM("github:acme/conflict", "revision-1")
	if _, err := memory.PutSnapshot(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	changed := existing
	changed.Metadata.Generator = "changed"
	fetcher := mapFetcher{results: map[string]FetchResult{
		"github:acme/conflict": {BOM: changed},
		"github:acme/wrong":    {BOM: ingestionTestBOM("github:evil/other", "revision-2")},
		"github:acme/good":     {BOM: ingestionTestBOM("github:acme/good", "revision-3")},
	}}
	results, err := (Orchestrator{Reader: memory, Writer: memory, Fetcher: fetcher, MaxConcurrency: 3}).Run(context.Background(), []Repository{
		{Source: "github:acme/conflict"}, {Source: "github:acme/wrong"}, {Source: "github:acme/good"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusConflict || !errors.Is(results[0].Err, store.ErrConflict) {
		t.Fatalf("conflict result = %#v", results[0])
	}
	if results[1].Status != StatusFailed || results[1].Err == nil {
		t.Fatalf("mismatched source result = %#v", results[1])
	}
	if results[2].Status != StatusPersisted || results[2].Err != nil {
		t.Fatalf("successful result = %#v", results[2])
	}
}

func TestOrchestratorValidatesConfiguration(t *testing.T) {
	memory := store.NewMemory()
	orchestrator := Orchestrator{Reader: memory, Writer: memory, Fetcher: &recordingFetcher{}, MaxConcurrency: 1}
	for name, repositories := range map[string][]Repository{
		"empty":     {{Source: " "}},
		"duplicate": {{Source: "github:acme/platform"}, {Source: "github:acme/platform"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := orchestrator.Run(context.Background(), repositories); err == nil {
				t.Fatal("invalid repositories were accepted")
			}
		})
	}
}

func TestOrchestratorRetriesOnlyTransientFailuresWithBoundedBackoff(t *testing.T) {
	memory := store.NewMemory()
	fetcher := &retryFetcher{source: "github:acme/retry", failures: 2, err: Transient(errors.New("provider unavailable"))}
	var waits []time.Duration
	orchestrator := Orchestrator{
		Reader: memory, Writer: memory, Fetcher: fetcher, MaxConcurrency: 1,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: 1500 * time.Millisecond},
		sleep: func(_ context.Context, duration time.Duration) error { waits = append(waits, duration); return nil },
	}
	results, err := orchestrator.Run(context.Background(), []Repository{{Source: fetcher.source}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusPersisted || results[0].Attempts != 3 || len(waits) != 2 || waits[0] != time.Second || waits[1] != 1500*time.Millisecond {
		t.Fatalf("result = %#v, waits = %#v", results[0], waits)
	}

	permanent := &retryFetcher{source: "github:acme/permanent", failures: 3, err: errors.New("authentication rejected")}
	orchestrator.Fetcher = permanent
	results, err = orchestrator.Run(context.Background(), []Repository{{Source: permanent.source}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusFailed || results[0].Attempts != 1 || results[0].FailureClass != "permanent" {
		t.Fatalf("permanent result = %#v", results[0])
	}
}

func TestOrchestratorTimesOutOneRepositoryWithoutFailingBatch(t *testing.T) {
	memory := store.NewMemory()
	fetcher := timeoutFetcher{}
	results, err := (Orchestrator{
		Reader: memory, Writer: memory, Fetcher: fetcher, MaxConcurrency: 2, RepositoryTimeout: 20 * time.Millisecond,
	}).Run(context.Background(), []Repository{{Source: "github:acme/slow"}, {Source: "github:acme/fast"}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusFailed || results[0].FailureClass != "timeout" || !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Fatalf("timeout result = %#v", results[0])
	}
	if results[1].Status != StatusPersisted || results[1].Err != nil {
		t.Fatalf("fast result = %#v", results[1])
	}
}

type recordingFetcher struct {
	result   FetchResult
	requests []FetchRequest
}

func (fetcher *recordingFetcher) Fetch(_ context.Context, request FetchRequest) (FetchResult, error) {
	fetcher.requests = append(fetcher.requests, request)
	return fetcher.result, nil
}

type mapFetcher struct{ results map[string]FetchResult }

func (fetcher mapFetcher) Fetch(_ context.Context, request FetchRequest) (FetchResult, error) {
	return fetcher.results[request.Source], nil
}

type concurrencyFetcher struct {
	active  atomic.Int32
	peak    atomic.Int32
	release chan struct{}
}

type retryFetcher struct {
	source   string
	failures int
	err      error
	calls    int
}

func (fetcher *retryFetcher) Fetch(_ context.Context, _ FetchRequest) (FetchResult, error) {
	fetcher.calls++
	if fetcher.calls <= fetcher.failures {
		return FetchResult{}, fetcher.err
	}
	return FetchResult{BOM: ingestionTestBOM(fetcher.source, "revision-1")}, nil
}

type timeoutFetcher struct{}

func (timeoutFetcher) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	if request.Source == "github:acme/slow" {
		<-ctx.Done()
		return FetchResult{}, ctx.Err()
	}
	return FetchResult{BOM: ingestionTestBOM(request.Source, "revision-1")}, nil
}

func (fetcher *concurrencyFetcher) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	active := fetcher.active.Add(1)
	defer fetcher.active.Add(-1)
	for {
		peak := fetcher.peak.Load()
		if active <= peak || fetcher.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	select {
	case <-fetcher.release:
		return FetchResult{BOM: ingestionTestBOM(request.Source, "revision-1")}, nil
	case <-ctx.Done():
		return FetchResult{}, ctx.Err()
	}
}

func ingestionTestBOM(source, revision string) model.AgentBOM {
	return model.AgentBOM{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata: model.DocumentMetadata{
			Source: source, Revision: revision, Generator: "ingestion-test", NormalizationVersion: "v1alpha1",
		},
		Assets: []model.Asset{},
	}
}
