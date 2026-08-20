package server

import (
	"context"
	"fmt"
	"time"
)

const (
	MinimumCredentialReloadInterval = time.Second
	MaximumCredentialReloadInterval = time.Hour
)

type CredentialReloadResult struct {
	OccurredAt time.Time
	Succeeded  bool
	Err        error
}

type CredentialReloadObserver func(CredentialReloadResult)

// WatchCredentialFile performs an immediate load and then polls until the
// context is cancelled. Reload failures are observed but do not discard the
// registry's last-known-good snapshot or stop later attempts.
func WatchCredentialFile(ctx context.Context, registry *CredentialRegistry, path string, interval time.Duration, observer CredentialReloadObserver) error {
	if ctx == nil || registry == nil || path == "" || observer == nil {
		return fmt.Errorf("complete credential watcher dependencies are required")
	}
	if interval < MinimumCredentialReloadInterval || interval > MaximumCredentialReloadInterval {
		return fmt.Errorf("credential reload interval must be between %s and %s", MinimumCredentialReloadInterval, MaximumCredentialReloadInterval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	return runCredentialFileWatcher(ctx, ticker.C, func() error { return ReloadCredentialFile(registry, path) }, observer, time.Now)
}

func runCredentialFileWatcher(ctx context.Context, ticks <-chan time.Time, reload func() error, observer CredentialReloadObserver, now func() time.Time) error {
	if ctx == nil || ticks == nil || reload == nil || observer == nil || now == nil {
		return fmt.Errorf("complete credential watcher runtime dependencies are required")
	}
	attempt := func() {
		err := reload()
		observer(CredentialReloadResult{OccurredAt: now().UTC(), Succeeded: err == nil, Err: err})
	}
	attempt()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return fmt.Errorf("credential watcher tick source closed")
			}
			attempt()
		}
	}
}
