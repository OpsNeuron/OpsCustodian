package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSpoolRetainsFailureAndReplaysIdempotently(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := &sequenceAuditSink{failures: []error{errors.New("database unavailable")}}
	sink, err := NewFileSpoolSink(target, directory, 10)
	if err != nil {
		t.Fatal(err)
	}
	event := validSinkTestEvent()
	if err := sink.Record(context.Background(), event); err == nil {
		t.Fatal("destination failure was ignored")
	}
	path := filepath.Join(directory, event.EventID+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pending event was not retained: %v", err)
	}
	if err := sink.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if target.attempts != 2 {
		t.Fatalf("target attempts = %d", target.attempts)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("acknowledged event remains in spool: %v", err)
	}
}

func TestFileSpoolRejectsTamperingAndEnforcesBound(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := &sequenceAuditSink{failures: []error{errors.New("offline"), errors.New("offline")}}
	sink, err := NewFileSpoolSink(target, directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := validSinkTestEvent()
	if err := sink.Record(context.Background(), first); err == nil {
		t.Fatal("first destination failure was ignored")
	}
	second := first
	second.Timestamp = "2026-10-01T00:00:01Z"
	second.EventID = deterministicEventID(second)
	if err := sink.Record(context.Background(), second); err == nil || err.Error() != "audit spool pending limit reached" {
		t.Fatalf("spool bound error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected.txt"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sink.Replay(context.Background()); err == nil {
		t.Fatal("unexpected spool entry was accepted")
	}
}

func TestFileSpoolRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewFileSpoolSink(&recordingAuditSink{}, "relative", 1); err == nil {
		t.Fatal("relative spool directory was accepted")
	}
	if _, err := NewFileSpoolSink(nil, t.TempDir(), 1); err == nil {
		t.Fatal("nil spool target was accepted")
	}
	var sink *FileSpoolSink
	if err := sink.Replay(context.Background()); err == nil {
		t.Fatal("nil spool sink was accepted")
	}
}
