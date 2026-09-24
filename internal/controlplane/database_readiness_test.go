package controlplane

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/server"
)

type readinessTestPinger struct {
	mu  sync.Mutex
	err error
}

func (pinger *readinessTestPinger) Ping(context.Context) error {
	pinger.mu.Lock()
	defer pinger.mu.Unlock()
	return pinger.err
}

func (pinger *readinessTestPinger) setError(err error) {
	pinger.mu.Lock()
	pinger.err = err
	pinger.mu.Unlock()
}

func TestMonitorDatabaseReadinessDetectsFailureAndRecovery(t *testing.T) {
	tracker := server.NewReadinessTracker(false, false)
	if err := tracker.Update(server.ReadinessDatabase, server.ReadinessReady); err != nil {
		t.Fatal(err)
	}
	pinger := &readinessTestPinger{err: errors.New("database unavailable")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go monitorDatabaseReadiness(ctx, pinger, tracker, time.Millisecond, 50*time.Millisecond)

	waitForDatabaseReadiness(t, tracker, server.ReadinessDegraded)
	pinger.setError(nil)
	waitForDatabaseReadiness(t, tracker, server.ReadinessReady)
}

func waitForDatabaseReadiness(t *testing.T, tracker *server.ReadinessTracker, expected string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tracker.Snapshot().Components[server.ReadinessDatabase] == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("database readiness did not become %q", expected)
}
