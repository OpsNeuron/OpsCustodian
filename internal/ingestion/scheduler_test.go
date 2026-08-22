package ingestion

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
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

type schedulerRunner struct {
	calls    int
	active   int
	peak     int
	failures int
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
