package ingestion

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

const (
	MinimumScheduleInterval = 10 * time.Second
	MaximumScheduleInterval = 24 * time.Hour
)

type BatchRunner interface {
	Run(context.Context, []Repository) ([]Result, error)
}

type LeaseAwareBatchRunner interface {
	RunWithLease(context.Context, []Repository, store.SchedulerLease) ([]Result, error)
}

type ScheduleObservation struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Results    []Result
	Err        error
	Standby    bool
	LeaseLost  bool
}

type ScheduleObserver func(ScheduleObservation) error

type Scheduler struct {
	Runner        BatchRunner
	Repositories  []Repository
	Interval      time.Duration
	MaxJitter     time.Duration
	Observer      ScheduleObserver
	LeaseStore    store.SchedulerLeaseStore
	LeaseName     string
	HolderID      string
	LeaseTTL      time.Duration
	RenewInterval time.Duration

	now       func() time.Time
	wait      func(context.Context, time.Duration) error
	leaseWait func(context.Context, time.Duration) error
	jitter    func(time.Duration) (time.Duration, error)
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
	if err := scheduler.validateLeaseConfiguration(); err != nil {
		return err
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
	if scheduler.LeaseStore != nil {
		return scheduler.runLeased(ctx, repositories, now, wait, jitter)
	}

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

func (scheduler Scheduler) validateLeaseConfiguration() error {
	configured := scheduler.LeaseStore != nil || scheduler.LeaseName != "" || scheduler.HolderID != "" || scheduler.LeaseTTL != 0 || scheduler.RenewInterval != 0
	if !configured {
		return nil
	}
	if scheduler.LeaseStore == nil || scheduler.LeaseName == "" || scheduler.HolderID == "" {
		return fmt.Errorf("complete ingestion scheduler lease dependencies are required")
	}
	if _, ok := scheduler.Runner.(LeaseAwareBatchRunner); !ok {
		return fmt.Errorf("ingestion batch runner does not support commit-time fencing")
	}
	if scheduler.LeaseTTL < store.MinimumLeaseTTL || scheduler.LeaseTTL > store.MaximumLeaseTTL {
		return fmt.Errorf("ingestion scheduler lease TTL must be between %s and %s", store.MinimumLeaseTTL, store.MaximumLeaseTTL)
	}
	if scheduler.RenewInterval <= 0 || scheduler.RenewInterval >= scheduler.LeaseTTL {
		return fmt.Errorf("ingestion scheduler lease renewal interval must be positive and less than the lease TTL")
	}
	return nil
}

func (scheduler Scheduler) runLeased(ctx context.Context, repositories []Repository, now func() time.Time, wait func(context.Context, time.Duration) error, jitter func(time.Duration) (time.Duration, error)) error {
	for ctx.Err() == nil {
		started := now().UTC()
		lease, acquired, acquireErr := scheduler.LeaseStore.AcquireSchedulerLease(ctx, scheduler.LeaseName, scheduler.HolderID, scheduler.LeaseTTL)
		if acquireErr != nil || !acquired {
			observation := ScheduleObservation{StartedAt: started, FinishedAt: now().UTC(), Standby: !acquired && acquireErr == nil, LeaseLost: acquireErr != nil}
			if acquireErr != nil {
				observation.Err = fmt.Errorf("acquire ingestion scheduler lease: %w", acquireErr)
			}
			if err := scheduler.observe(observation); err != nil {
				return err
			}
			delay, err := scheduler.nextDelay(jitter)
			if err != nil {
				return err
			}
			if delay > scheduler.RenewInterval {
				delay = scheduler.RenewInterval
			}
			if err := wait(ctx, delay); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("wait for ingestion schedule: %w", err)
			}
			continue
		}

		leadContext, cancelLeadership := context.WithCancel(ctx)
		renewal := make(chan error, 1)
		go func() { renewal <- scheduler.maintainLease(leadContext, cancelLeadership, lease) }()
		leadErr := scheduler.runLeadership(leadContext, repositories, lease, now, wait, jitter)
		cancelLeadership()
		renewErr := <-renewal
		released, releaseErr := scheduler.LeaseStore.ReleaseSchedulerLease(context.WithoutCancel(ctx), lease)
		if releaseErr != nil {
			releaseErr = fmt.Errorf("release ingestion scheduler lease: %w", releaseErr)
		} else if !released && renewErr == nil && ctx.Err() == nil {
			releaseErr = fmt.Errorf("release ingestion scheduler lease: ownership was lost")
		}
		if leadErr != nil {
			return errors.Join(leadErr, releaseErr)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err := errors.Join(renewErr, releaseErr); err != nil {
			observation := ScheduleObservation{StartedAt: now().UTC(), FinishedAt: now().UTC(), Err: err, LeaseLost: true}
			if observeErr := scheduler.observe(observation); observeErr != nil {
				return observeErr
			}
		}
	}
	return nil
}

func (scheduler Scheduler) runLeadership(ctx context.Context, repositories []Repository, lease store.SchedulerLease, now func() time.Time, wait func(context.Context, time.Duration) error, jitter func(time.Duration) (time.Duration, error)) error {
	for ctx.Err() == nil {
		started := now().UTC()
		results, runErr := scheduler.Runner.(LeaseAwareBatchRunner).RunWithLease(ctx, cloneRepositories(repositories), lease)
		if ctx.Err() != nil {
			return nil
		}
		observation := ScheduleObservation{StartedAt: started, FinishedAt: now().UTC(), Results: append([]Result(nil), results...), Err: runErr}
		if err := scheduler.observe(observation); err != nil {
			return err
		}
		delay, err := scheduler.nextDelay(jitter)
		if err != nil {
			return err
		}
		if err := wait(ctx, delay); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wait for ingestion schedule: %w", err)
		}
	}
	return nil
}

func (scheduler Scheduler) observe(observation ScheduleObservation) error {
	if err := scheduler.Observer(observation); err != nil {
		return fmt.Errorf("observe ingestion schedule: %w", err)
	}
	return nil
}

func (scheduler Scheduler) nextDelay(jitter func(time.Duration) (time.Duration, error)) (time.Duration, error) {
	extra, err := jitter(scheduler.MaxJitter)
	if err != nil {
		return 0, fmt.Errorf("generate ingestion schedule jitter: %w", err)
	}
	if extra < 0 || extra > scheduler.MaxJitter {
		return 0, fmt.Errorf("ingestion schedule jitter is outside configured bounds")
	}
	return scheduler.Interval + extra, nil
}

var errSchedulerLeaseLost = errors.New("ingestion scheduler lease lost")

func (scheduler Scheduler) maintainLease(ctx context.Context, cancel context.CancelFunc, lease store.SchedulerLease) error {
	wait := scheduler.leaseWait
	if wait == nil {
		wait = waitForSchedule
	}
	for {
		if err := wait(ctx, scheduler.RenewInterval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			cancel()
			return fmt.Errorf("wait to renew ingestion scheduler lease: %w", err)
		}
		renewed, ok, err := scheduler.LeaseStore.RenewSchedulerLease(ctx, lease, scheduler.LeaseTTL)
		if err != nil {
			cancel()
			return fmt.Errorf("renew ingestion scheduler lease: %w", err)
		}
		if !ok {
			cancel()
			return errSchedulerLeaseLost
		}
		lease = renewed
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
