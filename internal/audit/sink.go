package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type JSONLineSink struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

type Sink interface {
	Record(context.Context, Event) error
}

type MultiSink struct{ sinks []Sink }

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
	for _, target := range sink.sinks {
		if err := target.Record(ctx, event); err != nil {
			return err
		}
	}
	return nil
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
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err := sink.encoder.Encode(event); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}
