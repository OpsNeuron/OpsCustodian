package ingestion

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const (
	MinimumScheduleInterval = 10 * time.Second
	MaximumScheduleInterval = 24 * time.Hour
)

type BatchRunner interface {
	Run(context.Context, []Repository) ([]Result, error)
}

type ScheduleObservation struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Results    []Result
	Err        error
}

type ScheduleObserver func(ScheduleObservation) error

type Scheduler struct {
	Runner       BatchRunner
	Repositories []Repository
	Interval     time.Duration
	MaxJitter    time.Duration
	Observer     ScheduleObserver

	now    func() time.Time
	wait   func(context.Context, time.Duration) error
	jitter func(time.Duration) (time.Duration, error)
}

// Run executes one batch immediately and schedules the next delay only after
// the previous batch completes. This completion-based cadence prevents
// overlapping repository scans by construction.
func (scheduler Scheduler) Run(ctx context.Context) error {
	if ctx == nil || scheduler.Runner == nil || scheduler.Observer == nil || len(scheduler.Repositories) == 0 {
		return fmt.Errorf("complete ingestion scheduler dependencies are required")
	}
	if scheduler.Interval < MinimumScheduleInterval || scheduler.Interval > MaximumScheduleInterval {
		return fmt.Errorf("ingestion interval must be between %s and %s", MinimumScheduleInterval, MaximumScheduleInterval)
	}
	if scheduler.MaxJitter < 0 || scheduler.MaxJitter > scheduler.Interval {
		return fmt.Errorf("ingestion jitter must be between zero and the schedule interval")
	}
	now := scheduler.now
	if now == nil {
		now = time.Now
	}
	wait := scheduler.wait
	if wait == nil {
		wait = waitForSchedule
	}
	jitter := scheduler.jitter
	if jitter == nil {
		jitter = randomScheduleJitter
	}
	repositories := cloneRepositories(scheduler.Repositories)

	for {
		if ctx.Err() != nil {
			return nil
		}
		started := now().UTC()
		results, runErr := scheduler.Runner.Run(ctx, cloneRepositories(repositories))
		observation := ScheduleObservation{
			StartedAt: started, FinishedAt: now().UTC(), Results: append([]Result(nil), results...), Err: runErr,
		}
		if err := scheduler.Observer(observation); err != nil {
			return fmt.Errorf("observe ingestion schedule: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		extra, err := jitter(scheduler.MaxJitter)
		if err != nil {
			return fmt.Errorf("generate ingestion schedule jitter: %w", err)
		}
		if extra < 0 || extra > scheduler.MaxJitter {
			return fmt.Errorf("ingestion schedule jitter is outside configured bounds")
		}
		if err := wait(ctx, scheduler.Interval+extra); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wait for ingestion schedule: %w", err)
		}
	}
}

func cloneRepositories(repositories []Repository) []Repository {
	cloned := make([]Repository, len(repositories))
	for index, repository := range repositories {
		repository.Boundaries = append([]string(nil), repository.Boundaries...)
		cloned[index] = repository
	}
	return cloned
}

func waitForSchedule(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func randomScheduleJitter(maximum time.Duration) (time.Duration, error) {
	if maximum == 0 {
		return 0, nil
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return 0, err
	}
	return time.Duration(value.Int64()), nil
}
