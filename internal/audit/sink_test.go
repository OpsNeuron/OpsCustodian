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
	if err := sink.Record(context.Background(), validSinkTestEvent()); err == nil {
		t.Fatal("writer failure was ignored")
	}
	if _, err := NewJSONLineSink(nil); err == nil {
		t.Fatal("nil writer was accepted")
	}
}

func TestMultiSinkAttemptsEveryTargetAndReturnsJoinedFailures(t *testing.T) {
	firstFailure := errors.New("first failure")
	thirdFailure := errors.New("third failure")
	first := &recordingAuditSink{err: firstFailure}
	second := &recordingAuditSink{}
	third := &recordingAuditSink{err: thirdFailure}
	sink, err := NewMultiSink(first, second, third)
	if err != nil {
		t.Fatal(err)
	}
	event := validSinkTestEvent()
	err = sink.Record(context.Background(), event)
	if !errors.Is(err, firstFailure) || !errors.Is(err, thirdFailure) {
		t.Fatalf("Record() error = %v, expected both sink failures", err)
	}
	for index, target := range []*recordingAuditSink{first, second, third} {
		if len(target.events) != 1 || target.events[0].SchemaVersion != SchemaVersion {
			t.Fatalf("sink %d events = %#v, expected one attempted event", index+1, target.events)
		}
	}
}

func TestMultiSinkRejectsInvalidEventBeforeFanout(t *testing.T) {
	first := &recordingAuditSink{}
	second := &recordingAuditSink{}
	sink, err := NewMultiSink(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(context.Background(), Event{SchemaVersion: SchemaVersion}); err == nil {
		t.Fatal("invalid audit event was accepted")
	}
	if len(first.events) != 0 || len(second.events) != 0 {
		t.Fatalf("invalid event reached sinks: first=%d second=%d", len(first.events), len(second.events))
	}
}

func TestMultiSinkIsolatesTargetsFromEventMutation(t *testing.T) {
	recording := &recordingAuditSink{}
	sink, err := NewMultiSink(mutatingAuditSink{}, recording)
	if err != nil {
		t.Fatal(err)
	}
	event := validSinkTestEvent()
	event.Attributes["values"] = []string{"original"}
	if err := sink.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	values, ok := recording.events[0].Attributes["values"].([]string)
	if !ok || len(values) != 1 || values[0] != "original" || recording.events[0].EventName != event.EventName {
		t.Fatalf("later sink observed mutated event: %#v", recording.events[0])
	}
	if event.Attributes["mutated"] != nil || event.EventName != "opscustodian.credential.reload.completed" {
		t.Fatalf("caller event was mutated: %#v", event)
	}
}

func TestMultiSinkRejectsMissingTargets(t *testing.T) {
	if _, err := NewMultiSink(); err == nil {
		t.Fatal("empty sink set was accepted")
	}
	if _, err := NewMultiSink(&recordingAuditSink{}, nil); err == nil {
		t.Fatal("nil sink was accepted")
	}
	var sink *MultiSink
	if err := sink.Record(context.Background(), Event{}); err == nil {
		t.Fatal("nil multi-sink was accepted")
	}
}

type recordingAuditSink struct {
	events []Event
	err    error
}

func validSinkTestEvent() Event {
	return FromCredentialReload(CredentialReloadObservation{
		OccurredAt:     time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		OrganizationID: "organization-0123456789abcdef",
		Succeeded:      true,
	})
}

func (sink *recordingAuditSink) Record(_ context.Context, event Event) error {
	sink.events = append(sink.events, event)
	return sink.err
}

type failingAuditWriter struct{}

func (failingAuditWriter) Write([]byte) (int, error) { return 0, errors.New("disk failure") }

type mutatingAuditSink struct{}

func (mutatingAuditSink) Record(_ context.Context, event Event) error {
	event.EventName = "mutated"
	event.Attributes["mutated"] = true
	event.Attributes["values"].([]string)[0] = "mutated"
	return nil
}
