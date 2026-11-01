package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

type JSONLineSink struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

type Sink interface {
	Record(context.Context, Event) error
}

const (
	maxRetryAttempts = 10
	maxRetryBackoff  = time.Minute
)

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Retryable      func(error) bool
}

type retryableError interface {
	Retryable() bool
}

type RetrySink struct {
	target Sink
	policy RetryPolicy
	wait   func(context.Context, time.Duration) error
}

type MultiSink struct{ sinks []Sink }

func NewRetrySink(target Sink, policy RetryPolicy) (*RetrySink, error) {
	return newRetrySink(target, policy, waitForRetry)
}

func IsRetryableError(err error) bool {
	var marked retryableError
	return errors.As(err, &marked) && marked.Retryable()
}

func newRetrySink(target Sink, policy RetryPolicy, wait func(context.Context, time.Duration) error) (*RetrySink, error) {
	if target == nil || wait == nil {
		return nil, fmt.Errorf("audit retry dependencies must be initialized")
	}
	if policy.MaxAttempts < 1 || policy.MaxAttempts > maxRetryAttempts || policy.InitialBackoff <= 0 || policy.InitialBackoff > maxRetryBackoff || policy.MaxBackoff < policy.InitialBackoff || policy.MaxBackoff > maxRetryBackoff || policy.Retryable == nil {
		return nil, fmt.Errorf("audit retry policy is invalid")
	}
	return &RetrySink{target: target, policy: policy, wait: wait}, nil
}

func (sink *RetrySink) Record(ctx context.Context, event Event) error {
	if sink == nil || sink.target == nil || sink.wait == nil {
		return fmt.Errorf("audit retry sink is not initialized")
	}
	if err := ValidateEvent(event); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}

	backoff := sink.policy.InitialBackoff
	for attempt := 1; attempt <= sink.policy.MaxAttempts; attempt++ {
		err := sink.target.Record(ctx, cloneEvent(event))
		if err == nil {
			return nil
		}
		if attempt == sink.policy.MaxAttempts || !sink.policy.Retryable(err) {
			return fmt.Errorf("record audit event after %d attempt(s): %w", attempt, err)
		}
		if err := sink.wait(ctx, backoff); err != nil {
			return fmt.Errorf("wait to retry audit event after %d attempt(s): %w", attempt, err)
		}
		backoff = nextRetryBackoff(backoff, sink.policy.MaxBackoff)
	}
	return fmt.Errorf("record audit event retry exhausted")
}

func nextRetryBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum-current {
		return maximum
	}
	return current * 2
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func NewMultiSink(sinks ...Sink) (*MultiSink, error) {
	for _, sink := range sinks {
		if sink == nil {
			return nil, fmt.Errorf("audit sinks must be initialized")
		}
	}
	if len(sinks) == 0 {
		return nil, fmt.Errorf("at least one audit sink is required")
	}
	return &MultiSink{sinks: append([]Sink(nil), sinks...)}, nil
}

func (sink *MultiSink) Record(ctx context.Context, event Event) error {
	if sink == nil {
		return fmt.Errorf("audit sink is not initialized")
	}
	if err := ValidateEvent(event); err != nil {
		return err
	}
	var failures []error
	for index, target := range sink.sinks {
		if err := target.Record(ctx, cloneEvent(event)); err != nil {
			failures = append(failures, fmt.Errorf("record audit sink %d: %w", index+1, err))
		}
	}
	return errors.Join(failures...)
}

func cloneEvent(event Event) Event {
	cloned := event
	cloned.Resource = cloneFields(event.Resource)
	cloned.Attributes = cloneFields(event.Attributes)
	return cloned
}

func cloneFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	cloned := make(map[string]any, len(fields))
	for key, value := range fields {
		reflected := reflect.ValueOf(value)
		if reflected.IsValid() && (reflected.Kind() == reflect.Array || reflected.Kind() == reflect.Slice) {
			copyValue := reflect.New(reflected.Type()).Elem()
			if reflected.Kind() == reflect.Slice {
				copyValue = reflect.MakeSlice(reflected.Type(), reflected.Len(), reflected.Len())
			}
			reflect.Copy(copyValue, reflected)
			cloned[key] = copyValue.Interface()
			continue
		}
		cloned[key] = value
	}
	return cloned
}

func NewJSONLineSink(writer io.Writer) (*JSONLineSink, error) {
	if writer == nil {
		return nil, fmt.Errorf("audit writer is required")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &JSONLineSink{encoder: encoder}, nil
}

func (sink *JSONLineSink) Record(_ context.Context, event Event) error {
	if sink == nil || sink.encoder == nil {
		return fmt.Errorf("audit sink is not initialized")
	}
	if err := ValidateEvent(event); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err := sink.encoder.Encode(event); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}
