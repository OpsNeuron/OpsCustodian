package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestReadinessTrackerTransitionsWithoutDynamicDetails(t *testing.T) {
	tracker := NewReadinessTracker(true, true)
	if snapshot := tracker.Snapshot(); snapshot.Status != "not-ready" || snapshot.Components[ReadinessDatabase] != ReadinessStarting || snapshot.Components[ReadinessSchedulerRole] != ReadinessStarting || len(snapshot.Components) != 4 {
		t.Fatalf("initial snapshot = %#v", snapshot)
	}
	for _, component := range []string{ReadinessDatabase, ReadinessIngestion, ReadinessGitHubAuth} {
		if err := tracker.Update(component, ReadinessReady); err != nil {
			t.Fatal(err)
		}
	}
	if err := tracker.Update(ReadinessSchedulerRole, SchedulerRoleStandby); err != nil {
		t.Fatal(err)
	}
	if snapshot := tracker.Snapshot(); snapshot.Status != ReadinessReady {
		t.Fatalf("ready snapshot = %#v", snapshot)
	}
	if err := tracker.Update(ReadinessIngestion, ReadinessDegraded); err != nil {
		t.Fatal(err)
	}
	if snapshot := tracker.Snapshot(); snapshot.Status != "not-ready" || snapshot.Components[ReadinessIngestion] != ReadinessDegraded {
		t.Fatalf("degraded snapshot = %#v", snapshot)
	}
	if err := tracker.Update(ReadinessIngestion, ReadinessReady); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(ReadinessSchedulerRole, SchedulerRoleLeaseLost); err != nil {
		t.Fatal(err)
	}
	if snapshot := tracker.Snapshot(); snapshot.Status != "not-ready" || snapshot.Components[ReadinessSchedulerRole] != SchedulerRoleLeaseLost {
		t.Fatalf("lease-lost snapshot = %#v", snapshot)
	}
	if err := tracker.Update("repository:secret", ReadinessReady); err == nil {
		t.Fatal("dynamic component unexpectedly accepted")
	}
}

func TestReadinessEndpointIsPublicAndReturnsBounded503(t *testing.T) {
	tracker := NewReadinessTracker(true, false)
	handler := newHandlerWithReadiness(store.NewMemory(), "test", nil, nil, tracker)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var snapshot ReadinessSnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "not-ready" || len(snapshot.Components) != 4 || snapshot.Components[ReadinessSchedulerRole] != ReadinessStarting {
		t.Fatalf("response = %#v", snapshot)
	}
}
