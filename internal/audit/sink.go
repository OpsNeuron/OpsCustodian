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
