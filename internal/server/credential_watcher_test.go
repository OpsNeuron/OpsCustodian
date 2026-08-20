package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCredentialFileWatcherContinuesAfterFailureAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 2)
	attempts := 0
	results := make([]CredentialReloadResult, 0, 3)
	reloadFailure := errors.New("temporary reload failure")
	done := make(chan error, 1)
	go func() {
		done <- runCredentialFileWatcher(ctx, ticks, func() error {
			attempts++
			if attempts == 2 {
				return reloadFailure
			}
			return nil
		}, func(result CredentialReloadResult) {
			results = append(results, result)
			if len(results) == 3 {
				cancel()
			}
		}, func() time.Time { return time.Date(2026, 8, 20, 12, 0, attempts, 0, time.UTC) })
	}()
	ticks <- time.Now()
	ticks <- time.Now()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || !results[0].Succeeded || results[1].Succeeded || !errors.Is(results[1].Err, reloadFailure) || !results[2].Succeeded {
		t.Fatalf("reload results = %#v", results)
	}
}

func TestCredentialFileWatcherValidatesDependenciesAndBounds(t *testing.T) {
	registry, _ := NewCredentialRegistry([]BearerCredential{{ID: "watch-reader", Token: "watch-reader-token-0123456789abcdefghijkl", Scopes: []string{ScopeInventoryRead}}})
	for _, interval := range []time.Duration{0, time.Millisecond, MaximumCredentialReloadInterval + time.Second} {
		if err := WatchCredentialFile(context.Background(), registry, "credentials.json", interval, func(CredentialReloadResult) {}); err == nil {
			t.Fatalf("invalid interval accepted: %s", interval)
		}
	}
	if err := WatchCredentialFile(context.Background(), registry, "credentials.json", time.Second, nil); err == nil {
		t.Fatal("nil observer accepted")
	}
}

func TestCredentialFileWatcherReportsClosedTickSource(t *testing.T) {
	ticks := make(chan time.Time)
	close(ticks)
	err := runCredentialFileWatcher(context.Background(), ticks, func() error { return nil }, func(CredentialReloadResult) {}, time.Now)
	if err == nil {
		t.Fatal("closed tick source was accepted")
	}
}
