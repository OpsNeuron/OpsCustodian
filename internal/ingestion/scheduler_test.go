package ingestion

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestSchedulerRunsImmediatelyWithoutOverlapAndAppliesJitter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &schedulerRunner{}
	var observations []ScheduleObservation
	var waits []time.Duration
	times := []time.Time{
		time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 22, 10, 0, 2, 0, time.UTC),
		time.Date(2026, 8, 22, 10, 1, 7, 0, time.UTC),
		time.Date(2026, 8, 22, 10, 1, 10, 0, time.UTC),
	}
	scheduler := Scheduler{
		Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute, MaxJitter: 5 * time.Second,
		Observer: func(observation ScheduleObservation) error {
			observations = append(observations, observation)
			return nil
		},
		now:    func() time.Time { value := times[0]; times = times[1:]; return value },
		jitter: func(time.Duration) (time.Duration, error) { return 5 * time.Second, nil },
		wait: func(ctx context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			if len(waits) == 2 {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	}
	if err := scheduler.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 2 || runner.peak != 1 || len(observations) != 2 {
		t.Fatalf("calls = %d, peak = %d, observations = %#v", runner.calls, runner.peak, observations)
	}
	if !reflect.DeepEqual(waits, []time.Duration{65 * time.Second, 65 * time.Second}) {
		t.Fatalf("waits = %#v", waits)
	}
	if observations[0].StartedAt != time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC) || observations[0].FinishedAt.Sub(observations[0].StartedAt) != 2*time.Second {
		t.Fatalf("first observation = %#v", observations[0])
	}
}

func TestSchedulerObservesBatchFailureAndContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &schedulerRunner{failures: 1}
	var observed []error
	scheduler := Scheduler{
		Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute,
		Observer: func(observation ScheduleObservation) error { observed = append(observed, observation.Err); return nil },
		wait: func(context.Context, time.Duration) error {
			if runner.calls == 2 {
				cancel()
				return context.Canceled
			}
			return nil
		},
	}
	if err := scheduler.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 2 || observed[0] == nil || observed[1] != nil {
		t.Fatalf("calls = %d, observed = %#v", runner.calls, observed)
	}
}

func TestSchedulerFailsClosedOnObserverOrJitterFailure(t *testing.T) {
	runner := &schedulerRunner{}
	base := Scheduler{Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute}
	base.Observer = func(ScheduleObservation) error { return errors.New("audit unavailable") }
	if err := base.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("observer failure = %v", err)
	}
	base.Observer = func(ScheduleObservation) error { return nil }
	base.jitter = func(time.Duration) (time.Duration, error) { return 0, errors.New("entropy unavailable") }
	if err := base.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("jitter failure = %v", err)
	}
}

func TestSchedulerLeaseLeaderRunsAndReleasesWhileStandbyDoesNotRun(t *testing.T) {
	for _, test := range []struct {
		name        string
		acquired    bool
		wantCalls   int
		wantStandby bool
	}{
		{name: "leader", acquired: true, wantCalls: 1},
		{name: "standby", acquired: false, wantStandby: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			runner := &schedulerRunner{}
			leases := &schedulerLeaseStore{acquired: test.acquired, released: true}
			var observed ScheduleObservation
			var waited time.Duration
			scheduler := Scheduler{
				Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute,
				Observer:   func(value ScheduleObservation) error { observed = value; return nil },
				LeaseStore: leases, LeaseName: "repository-ingestion", HolderID: "instance-a",
				LeaseTTL: time.Minute, RenewInterval: 20 * time.Second,
				wait: func(_ context.Context, duration time.Duration) error {
					waited = duration
					cancel()
					return context.Canceled
				},
			}
			if err := scheduler.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if runner.calls != test.wantCalls || observed.Standby != test.wantStandby || observed.Err != nil {
				t.Fatalf("runner calls = %d, observation = %#v", runner.calls, observed)
			}
			if test.acquired && leases.releaseCalls != 1 {
				t.Fatalf("leader release calls = %d", leases.releaseCalls)
			}
			if !test.acquired && leases.releaseCalls != 0 {
				t.Fatalf("standby release calls = %d", leases.releaseCalls)
			}
			if test.wantStandby && waited != 20*time.Second {
				t.Fatalf("standby retry delay = %s, want renewal interval", waited)
			}
		})
	}
}

func TestSchedulerCancelsBatchAndReportsLostLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leases := &schedulerLeaseStore{acquired: true, released: false, loseOnRenew: true}
	runner := &cancellableSchedulerRunner{started: make(chan struct{})}
	var observed ScheduleObservation
	scheduler := Scheduler{
		Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute,
		Observer: func(value ScheduleObservation) error {
			observed = value
			if value.LeaseLost {
				cancel()
			}
			return nil
		},
		LeaseStore: leases, LeaseName: "repository-ingestion", HolderID: "instance-a",
		LeaseTTL: time.Minute, RenewInterval: 20 * time.Second,
		leaseWait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-runner.started:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	if err := scheduler.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !runner.cancelled || !observed.LeaseLost || !errors.Is(observed.Err, errSchedulerLeaseLost) {
		t.Fatalf("cancelled = %v, observation = %#v", runner.cancelled, observed)
	}
	if leases.renewCalls != 1 || leases.releaseCalls != 1 {
		t.Fatalf("lease calls = renew %d, release %d", leases.renewCalls, leases.releaseCalls)
	}
}

func TestSchedulerHoldsAndRenewsLeadershipAcrossScheduleIntervals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	renewed := make(chan struct{}, 1)
	leases := &schedulerLeaseStore{acquired: true, released: true, renewed: renewed}
	runner := &schedulerRunner{}
	waits := 0
	leaseWaits := 0
	scheduler := Scheduler{
		Runner: runner, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute,
		Observer:   func(ScheduleObservation) error { return nil },
		LeaseStore: leases, LeaseName: "repository-ingestion", HolderID: "instance-a",
		LeaseTTL: time.Minute, RenewInterval: 20 * time.Second,
		leaseWait: func(ctx context.Context, _ time.Duration) error {
			leaseWaits++
			if leaseWaits == 1 {
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		},
		wait: func(ctx context.Context, _ time.Duration) error {
			waits++
			if waits == 1 {
				select {
				case <-renewed:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			cancel()
			return ctx.Err()
		},
	}
	if err := scheduler.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 2 || leases.acquireCalls != 1 || leases.renewCalls != 1 || leases.releaseCalls != 1 {
		t.Fatalf("runner calls = %d, lease calls = acquire %d renew %d release %d", runner.calls, leases.acquireCalls, leases.renewCalls, leases.releaseCalls)
	}
}

func TestSchedulerRejectsPartialOrUnsafeLeaseConfiguration(t *testing.T) {
	base := Scheduler{
		Runner: &schedulerRunner{}, Repositories: []Repository{{Source: "github:acme/platform"}}, Interval: time.Minute,
		Observer: func(ScheduleObservation) error { return nil },
	}
	base.LeaseStore = &schedulerLeaseStore{}
	if err := base.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "complete ingestion scheduler lease") {
		t.Fatalf("partial lease configuration error = %v", err)
	}
	base.LeaseName, base.HolderID, base.LeaseTTL, base.RenewInterval = "repository-ingestion", "instance-a", time.Minute, time.Minute
	if err := base.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "less than") {
		t.Fatalf("unsafe renewal configuration error = %v", err)
	}
}

type schedulerRunner struct {
	calls    int
	active   int
	peak     int
	failures int
}

type schedulerLeaseStore struct {
	acquired     bool
	released     bool
	loseOnRenew  bool
	renewCalls   int
	releaseCalls int
	acquireCalls int
	renewed      chan struct{}
}

func (value *schedulerLeaseStore) AcquireSchedulerLease(context.Context, string, string, time.Duration) (store.SchedulerLease, bool, error) {
	value.acquireCalls++
	return store.SchedulerLease{Name: "repository-ingestion", HolderID: "instance-a", FencingToken: 1}, value.acquired, nil
}

func (value *schedulerLeaseStore) RenewSchedulerLease(_ context.Context, lease store.SchedulerLease, _ time.Duration) (store.SchedulerLease, bool, error) {
	value.renewCalls++
	if value.renewed != nil {
		value.renewed <- struct{}{}
	}
	return lease, !value.loseOnRenew, nil
}

func (value *schedulerLeaseStore) ReleaseSchedulerLease(context.Context, store.SchedulerLease) (bool, error) {
	value.releaseCalls++
	return value.released, nil
}

type cancellableSchedulerRunner struct {
	started   chan struct{}
	cancelled bool
}

func (runner *cancellableSchedulerRunner) Run(ctx context.Context, _ []Repository) ([]Result, error) {
	close(runner.started)
	<-ctx.Done()
	runner.cancelled = true
	return nil, ctx.Err()
}

func (runner *cancellableSchedulerRunner) RunWithLease(ctx context.Context, repositories []Repository, _ store.SchedulerLease) ([]Result, error) {
	return runner.Run(ctx, repositories)
}

func (runner *schedulerRunner) Run(_ context.Context, repositories []Repository) ([]Result, error) {
	runner.calls++
	runner.active++
	if runner.active > runner.peak {
		runner.peak = runner.active
	}
	defer func() { runner.active-- }()
	if runner.calls <= runner.failures {
		return nil, errors.New("batch failed")
	}
	return []Result{{Source: repositories[0].Source, Status: StatusUnchanged}}, nil
}

func (runner *schedulerRunner) RunWithLease(ctx context.Context, repositories []Repository, _ store.SchedulerLease) ([]Result, error) {
	return runner.Run(ctx, repositories)
}
