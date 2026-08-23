package ingestion

import (
	"context"
	"time"
)

const (
	GitHubAuthOperationCache         = "installation-token-cache"
	GitHubAuthOperationTokenExchange = "installation-token-exchange"
	GitHubAuthResultHit              = "hit"
	GitHubAuthResultRefreshed        = "refreshed"
	GitHubAuthResultSucceeded        = "succeeded"
	GitHubAuthResultRateLimited      = "rate-limited"
	GitHubAuthResultRejected         = "rejected"
	GitHubAuthResultFailed           = "failed"
	GitHubAuthResultCancelled        = "cancelled"
)

type GitHubAuthObservation struct {
	OccurredAt     time.Time
	Operation      string
	Result         string
	Transient      bool
	HTTPStatus     int
	DurationMillis int64
}

type GitHubAuthObserver func(context.Context, GitHubAuthObservation) error
