package server

import (
	"fmt"
	"sync"
)

const (
	ReadinessDatabase      = "database"
	ReadinessIngestion     = "ingestion"
	ReadinessGitHubAuth    = "github-auth"
	ReadinessSchedulerRole = "scheduler-role"

	ReadinessStarting      = "starting"
	ReadinessReady         = "ready"
	ReadinessDegraded      = "degraded"
	ReadinessDisabled      = "disabled"
	SchedulerRoleLeader    = "leader"
	SchedulerRoleStandby   = "standby"
	SchedulerRoleLeaseLost = "lease-lost"
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
	schedulerRole := ReadinessDisabled
	if ingestionConfigured {
		schedulerRole = ReadinessStarting
	}
	return &ReadinessTracker{components: map[string]string{
		ReadinessDatabase: ReadinessStarting, ReadinessIngestion: ingestionStatus, ReadinessGitHubAuth: githubStatus, ReadinessSchedulerRole: schedulerRole,
	}}
}

func (tracker *ReadinessTracker) Update(component, status string) error {
	if tracker == nil {
		return fmt.Errorf("readiness tracker is required")
	}
	if component != ReadinessDatabase && component != ReadinessIngestion && component != ReadinessGitHubAuth && component != ReadinessSchedulerRole {
		return fmt.Errorf("readiness component is invalid")
	}
	validStatus := status == ReadinessStarting || status == ReadinessReady || status == ReadinessDegraded || status == ReadinessDisabled
	validRole := status == SchedulerRoleLeader || status == SchedulerRoleStandby || status == SchedulerRoleLeaseLost
	if (component == ReadinessSchedulerRole && !validRole && status != ReadinessStarting && status != ReadinessDisabled) || (component != ReadinessSchedulerRole && !validStatus) {
		return fmt.Errorf("readiness status is invalid")
	}
	tracker.mu.Lock()
	tracker.components[component] = status
	tracker.mu.Unlock()
	return nil
}

func (tracker *ReadinessTracker) Snapshot() ReadinessSnapshot {
	components := map[string]string{
		ReadinessDatabase: ReadinessDegraded, ReadinessIngestion: ReadinessDegraded, ReadinessGitHubAuth: ReadinessDegraded, ReadinessSchedulerRole: SchedulerRoleLeaseLost,
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
		if component == ReadinessStarting || component == ReadinessDegraded || component == SchedulerRoleLeaseLost {
			status = "not-ready"
			break
		}
	}
	return ReadinessSnapshot{Status: status, Components: components}
}

type readyReadiness struct{}

func (readyReadiness) Snapshot() ReadinessSnapshot {
	return ReadinessSnapshot{Status: ReadinessReady, Components: map[string]string{
		ReadinessDatabase: ReadinessReady, ReadinessIngestion: ReadinessDisabled, ReadinessGitHubAuth: ReadinessDisabled, ReadinessSchedulerRole: ReadinessDisabled,
	}}
}
