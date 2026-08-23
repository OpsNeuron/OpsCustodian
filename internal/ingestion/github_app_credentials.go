package ingestion

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	githubAppInstallationPrefix = "github-app:installation:"
	defaultGitHubAppRefreshLead = 5 * time.Minute
	maximumGitHubAppTokenLife   = 2 * time.Hour
)

type GitHubAppInstallationToken struct {
	Value     string
	ExpiresAt time.Time
}

type GitHubAppTokenProvider interface {
	InstallationToken(context.Context, int64) (GitHubAppInstallationToken, error)
}

type GitHubAppCredentialOptions struct {
	Provider    GitHubAppTokenProvider
	RefreshLead time.Duration
	Now         func() time.Time
	Observer    GitHubAuthObserver
}

type githubAppCacheEntry struct {
	token     string
	expiresAt time.Time
}

type githubAppTokenFlight struct {
	done chan struct{}
}

type GitHubAppCredentialResolver struct {
	provider    GitHubAppTokenProvider
	refreshLead time.Duration
	now         func() time.Time
	observer    GitHubAuthObserver

	mu       sync.Mutex
	cache    map[int64]githubAppCacheEntry
	inFlight map[int64]*githubAppTokenFlight
}

func NewGitHubAppCredentialResolver(options GitHubAppCredentialOptions) (*GitHubAppCredentialResolver, error) {
	if options.Provider == nil {
		return nil, fmt.Errorf("GitHub App token provider is required")
	}
	refreshLead := options.RefreshLead
	if refreshLead == 0 {
		refreshLead = defaultGitHubAppRefreshLead
	}
	if refreshLead < 0 || refreshLead > time.Hour {
		return nil, fmt.Errorf("GitHub App token refresh lead must be between zero and one hour")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &GitHubAppCredentialResolver{
		provider: options.Provider, refreshLead: refreshLead, now: now, observer: options.Observer,
		cache: make(map[int64]githubAppCacheEntry), inFlight: make(map[int64]*githubAppTokenFlight),
	}, nil
}

func (resolver *GitHubAppCredentialResolver) Resolve(ctx context.Context, reference string) (string, error) {
	if resolver == nil || resolver.provider == nil || resolver.now == nil {
		return "", errors.New("GitHub App credential resolver is unavailable")
	}
	installationID, err := ParseGitHubAppCredentialReference(reference)
	if err != nil {
		return "", err
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		now := resolver.now()
		resolver.mu.Lock()
		if entry, ok := resolver.cache[installationID]; ok && entry.expiresAt.After(now.Add(resolver.refreshLead)) {
			resolver.mu.Unlock()
			if err := resolver.observe(ctx, GitHubAuthResultHit, now); err != nil {
				return "", err
			}
			return entry.token, nil
		}
		if flight, ok := resolver.inFlight[installationID]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-flight.done:
				continue
			}
		}
		flight := &githubAppTokenFlight{done: make(chan struct{})}
		resolver.inFlight[installationID] = flight
		resolver.mu.Unlock()

		token, providerErr := resolver.provider.InstallationToken(ctx, installationID)
		if providerErr == nil {
			providerErr = validateGitHubAppInstallationToken(token, now, resolver.refreshLead)
		}

		resolver.mu.Lock()
		if providerErr == nil {
			resolver.cache[installationID] = githubAppCacheEntry{token: token.Value, expiresAt: token.ExpiresAt}
		} else {
			delete(resolver.cache, installationID)
		}
		delete(resolver.inFlight, installationID)
		close(flight.done)
		resolver.mu.Unlock()

		if providerErr != nil {
			if isTransient(providerErr) {
				return "", Transient(errors.New("GitHub App installation token acquisition failed"))
			}
			return "", errors.New("GitHub App installation token acquisition failed")
		}
		if err := resolver.observe(ctx, GitHubAuthResultRefreshed, now); err != nil {
			return "", err
		}
		return token.Value, nil
	}
}

func (resolver *GitHubAppCredentialResolver) observe(ctx context.Context, result string, startedAt time.Time) error {
	if resolver.observer == nil {
		return nil
	}
	if err := resolver.observer(ctx, GitHubAuthObservation{
		OccurredAt: startedAt, Operation: GitHubAuthOperationCache, Result: result,
		DurationMillis: max(resolver.now().Sub(startedAt).Milliseconds(), 0),
	}); err != nil {
		return errors.New("GitHub authentication observation failed")
	}
	return nil
}

func ParseGitHubAppCredentialReference(reference string) (int64, error) {
	if !strings.HasPrefix(reference, githubAppInstallationPrefix) {
		return 0, fmt.Errorf("GitHub App credential reference must use github-app:installation:<id>")
	}
	value := strings.TrimPrefix(reference, githubAppInstallationPrefix)
	if value == "" || len(value) > 19 || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("GitHub App installation ID is invalid")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("GitHub App installation ID is invalid")
		}
	}
	installationID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || installationID <= 0 {
		return 0, fmt.Errorf("GitHub App installation ID is invalid")
	}
	return installationID, nil
}

func validateGitHubAppInstallationToken(token GitHubAppInstallationToken, now time.Time, refreshLead time.Duration) error {
	if err := validateGitHubToken(token.Value); err != nil {
		return fmt.Errorf("installation token is invalid")
	}
	if token.ExpiresAt.IsZero() || !token.ExpiresAt.After(now.Add(refreshLead)) {
		return fmt.Errorf("installation token expires too soon")
	}
	if token.ExpiresAt.After(now.Add(maximumGitHubAppTokenLife)) {
		return fmt.Errorf("installation token expiry exceeds maximum lifetime")
	}
	return nil
}
