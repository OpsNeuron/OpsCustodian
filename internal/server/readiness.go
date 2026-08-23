package server

import (
	"fmt"
	"sync"
)

const (
	ReadinessDatabase   = "database"
	ReadinessIngestion  = "ingestion"
	ReadinessGitHubAuth = "github-auth"

	ReadinessStarting = "starting"
	ReadinessReady    = "ready"
	ReadinessDegraded = "degraded"
	ReadinessDisabled = "disabled"
)

type ReadinessSnapshot struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
}

type ReadinessReader interface {
	Snapshot() ReadinessSnapshot
}

type ReadinessTracker struct {
	mu         sync.RWMutex
	components map[string]string
}

func NewReadinessTracker(ingestionConfigured, githubAuthConfigured bool) *ReadinessTracker {
	ingestionStatus := ReadinessDisabled
	if ingestionConfigured {
		ingestionStatus = ReadinessStarting
	}
	githubStatus := ReadinessDisabled
	if githubAuthConfigured {
		githubStatus = ReadinessStarting
	}
	return &ReadinessTracker{components: map[string]string{
		ReadinessDatabase: ReadinessStarting, ReadinessIngestion: ingestionStatus, ReadinessGitHubAuth: githubStatus,
	}}
}

func (tracker *ReadinessTracker) Update(component, status string) error {
	if tracker == nil {
		return fmt.Errorf("readiness tracker is required")
	}
	if component != ReadinessDatabase && component != ReadinessIngestion && component != ReadinessGitHubAuth {
		return fmt.Errorf("readiness component is invalid")
	}
	if status != ReadinessStarting && status != ReadinessReady && status != ReadinessDegraded && status != ReadinessDisabled {
		return fmt.Errorf("readiness status is invalid")
	}
	tracker.mu.Lock()
	tracker.components[component] = status
	tracker.mu.Unlock()
	return nil
}

func (tracker *ReadinessTracker) Snapshot() ReadinessSnapshot {
	components := map[string]string{
		ReadinessDatabase: ReadinessDegraded, ReadinessIngestion: ReadinessDegraded, ReadinessGitHubAuth: ReadinessDegraded,
	}
	if tracker != nil {
		tracker.mu.RLock()
		for component, status := range tracker.components {
			components[component] = status
		}
		tracker.mu.RUnlock()
	}
	status := ReadinessReady
	for _, component := range components {
		if component == ReadinessStarting || component == ReadinessDegraded {
			status = "not-ready"
			break
		}
	}
	return ReadinessSnapshot{Status: status, Components: components}
}

type readyReadiness struct{}

func (readyReadiness) Snapshot() ReadinessSnapshot {
	return ReadinessSnapshot{Status: ReadinessReady, Components: map[string]string{
		ReadinessDatabase: ReadinessReady, ReadinessIngestion: ReadinessDisabled, ReadinessGitHubAuth: ReadinessDisabled,
	}}
}
