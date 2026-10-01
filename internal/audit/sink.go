package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
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
