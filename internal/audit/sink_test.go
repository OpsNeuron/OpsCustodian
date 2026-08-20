package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestJSONLineSinkSerializesConcurrentEventsWithoutInterleaving(t *testing.T) {
	var output bytes.Buffer
	sink, err := NewJSONLineSink(&output)
	if err != nil {
		t.Fatal(err)
	}
	const count = 64
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			event := FromHTTPRequest(HTTPRequestObservation{
				OccurredAt: time.Unix(int64(index), 0), RequestID: "request", OrganizationID: "organization-0123456789abcdef",
				Method: "GET", Route: "GET /healthz", Status: 200, Authentication: "public",
			})
			if err := sink.Record(context.Background(), event); err != nil {
				t.Errorf("Record() error: %v", err)
			}
		}(index)
	}
	group.Wait()

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	lines := 0
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || event.SchemaVersion != SchemaVersion {
			t.Fatalf("invalid JSONL event: %s, %v", scanner.Bytes(), err)
		}
		lines++
	}
	if err := scanner.Err(); err != nil || lines != count {
		t.Fatalf("JSONL lines = %d, error = %v", lines, err)
	}
}

func TestJSONLineSinkReportsWriterFailure(t *testing.T) {
	sink, err := NewJSONLineSink(failingAuditWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(context.Background(), Event{SchemaVersion: SchemaVersion}); err == nil {
		t.Fatal("writer failure was ignored")
	}
	if _, err := NewJSONLineSink(nil); err == nil {
		t.Fatal("nil writer was accepted")
	}
}

type failingAuditWriter struct{}

func (failingAuditWriter) Write([]byte) (int, error) { return 0, errors.New("disk failure") }
