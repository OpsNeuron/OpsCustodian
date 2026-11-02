package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPercentileUsesNearestRank(t *testing.T) {
	values := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond}
	for _, test := range []struct {
		percent int
		want    time.Duration
	}{{50, 3 * time.Millisecond}, {95, 5 * time.Millisecond}, {99, 5 * time.Millisecond}, {100, 5 * time.Millisecond}} {
		if got := percentile(values, test.percent); got != test.want {
			t.Fatalf("percentile(%d) = %s, want %s", test.percent, got, test.want)
		}
	}
}

func TestReadFixtureRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(`{"metadata":{"revision":"one"}} {"metadata":{"revision":"two"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixture(path); err == nil {
		t.Fatal("readFixture() accepted trailing JSON")
	}
}

func TestFixtureWithRevisionDoesNotMutateTemplate(t *testing.T) {
	fixture := map[string]any{"apiVersion": "opscustodian.dev/v1alpha1", "metadata": map[string]any{"revision": "original"}}
	payload, err := fixtureWithRevision(fixture, "soak-1-1")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if document["metadata"].(map[string]any)["revision"] != "soak-1-1" {
		t.Fatalf("generated payload = %s", payload)
	}
	if fixture["metadata"].(map[string]any)["revision"] != "original" {
		t.Fatalf("fixture mutated: %#v", fixture)
	}
}

func TestValidRevisionPrefix(t *testing.T) {
	for _, value := range []string{"soak", "reference-1", "a1"} {
		if !validRevisionPrefix(value) {
			t.Fatalf("validRevisionPrefix(%q) = false", value)
		}
	}
	for _, value := range []string{"", "SOAK", "has space", "../escape"} {
		if validRevisionPrefix(value) {
			t.Fatalf("validRevisionPrefix(%q) = true", value)
		}
	}
}

func TestWorkerIntervalCapsAggregateRate(t *testing.T) {
	if got := workerInterval(4, 20); got != 200*time.Millisecond {
		t.Fatalf("workerInterval(4, 20) = %s", got)
	}
	if got := workerInterval(1, 5000); got != time.Millisecond {
		t.Fatalf("minimum worker interval = %s", got)
	}
}
