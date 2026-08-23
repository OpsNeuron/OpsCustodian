package ingestion

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeGitHubAppTokenProvider struct {
	mu      sync.Mutex
	calls   int
	token   GitHubAppInstallationToken
	err     error
	started chan struct{}
	release chan struct{}
}

func (provider *fakeGitHubAppTokenProvider) InstallationToken(ctx context.Context, installationID int64) (GitHubAppInstallationToken, error) {
	provider.mu.Lock()
	provider.calls++
	started := provider.started
	release := provider.release
	provider.mu.Unlock()
	if installationID != 42 {
		return GitHubAppInstallationToken{}, errors.New("unexpected installation")
	}
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return GitHubAppInstallationToken{}, ctx.Err()
		case <-release:
		}
	}
	return provider.token, provider.err
}

func (provider *fakeGitHubAppTokenProvider) callCount() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.calls
}

func TestGitHubAppCredentialResolverCachesAndRefreshesBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	provider := &fakeGitHubAppTokenProvider{token: GitHubAppInstallationToken{Value: "installation-token-one", ExpiresAt: now.Add(time.Hour)}}
	resolver, err := NewGitHubAppCredentialResolver(GitHubAppCredentialOptions{Provider: provider, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if token, err := resolver.Resolve(context.Background(), "github-app:installation:42"); err != nil || token != "installation-token-one" {
			t.Fatalf("Resolve() = %q, %v", token, err)
		}
	}
	if provider.callCount() != 1 {
		t.Fatalf("provider calls = %d, expected 1", provider.callCount())
	}

	now = now.Add(56 * time.Minute)
	provider.token = GitHubAppInstallationToken{Value: "installation-token-two", ExpiresAt: now.Add(time.Hour)}
	if token, err := resolver.Resolve(context.Background(), "github-app:installation:42"); err != nil || token != "installation-token-two" {
		t.Fatalf("refreshed Resolve() = %q, %v", token, err)
	}
	if provider.callCount() != 2 {
		t.Fatalf("provider calls = %d, expected 2", provider.callCount())
	}
}

func TestGitHubAppCredentialResolverCoalescesConcurrentRefresh(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	provider := &fakeGitHubAppTokenProvider{
		token:   GitHubAppInstallationToken{Value: "installation-token", ExpiresAt: now.Add(time.Hour)},
		started: make(chan struct{}, 1), release: make(chan struct{}),
	}
	resolver, _ := NewGitHubAppCredentialResolver(GitHubAppCredentialOptions{Provider: provider, Now: func() time.Time { return now }})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			token, err := resolver.Resolve(context.Background(), "github-app:installation:42")
			if err == nil && token != "installation-token" {
				err = errors.New("unexpected token")
			}
			results <- err
		}()
	}
	<-provider.started
	close(provider.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if provider.callCount() != 1 {
		t.Fatalf("provider calls = %d, expected 1", provider.callCount())
	}
}

func TestGitHubAppCredentialResolverRejectsUnsafeReferencesAndTokens(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	provider := &fakeGitHubAppTokenProvider{token: GitHubAppInstallationToken{Value: "secret-value", ExpiresAt: now.Add(time.Minute)}, err: errors.New("backend secret detail")}
	resolver, _ := NewGitHubAppCredentialResolver(GitHubAppCredentialOptions{Provider: provider, Now: func() time.Time { return now }})
	for _, reference := range []string{"env:OPSCUSTODIAN_GITHUB_TOKEN_X", "github-app:installation:", "github-app:installation:0", "github-app:installation:01", "github-app:installation:-1"} {
		if _, err := resolver.Resolve(context.Background(), reference); err == nil {
			t.Fatalf("Resolve(%q) unexpectedly succeeded", reference)
		}
	}
	_, err := resolver.Resolve(context.Background(), "github-app:installation:42")
	if err == nil || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "backend secret detail") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestGitHubAppCredentialResolverHonorsWaitingCallerCancellation(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	provider := &fakeGitHubAppTokenProvider{
		token:   GitHubAppInstallationToken{Value: "installation-token", ExpiresAt: now.Add(time.Hour)},
		started: make(chan struct{}, 1), release: make(chan struct{}),
	}
	resolver, _ := NewGitHubAppCredentialResolver(GitHubAppCredentialOptions{Provider: provider, Now: func() time.Time { return now }})
	firstDone := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(context.Background(), "github-app:installation:42")
		firstDone <- err
	}()
	<-provider.started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(ctx, "github-app:installation:42"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() error = %v, expected context cancellation", err)
	}
	close(provider.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestGitHubAppCredentialResolverRejectsExcessiveTokenLifetime(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	provider := &fakeGitHubAppTokenProvider{token: GitHubAppInstallationToken{Value: "installation-token", ExpiresAt: now.Add(24 * time.Hour)}}
	resolver, _ := NewGitHubAppCredentialResolver(GitHubAppCredentialOptions{Provider: provider, Now: func() time.Time { return now }})
	if _, err := resolver.Resolve(context.Background(), "github-app:installation:42"); err == nil {
		t.Fatal("Resolve() unexpectedly accepted a long-lived installation token")
	}
}
