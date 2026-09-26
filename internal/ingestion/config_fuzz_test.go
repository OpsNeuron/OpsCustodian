package ingestion

import (
	"encoding/json"
	"testing"
)

func FuzzParseRepositorySet(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"apiVersion":"opscustodian.dev/ingestion/v1alpha1","kind":"RepositorySet","schedule":{"interval":"1m","maxConcurrency":1},"repositories":[{"source":"local:test","connector":"local","location":"/tmp/test","revision":"main"}]}`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`{"unknown":true}`),
		[]byte("{}\n{}"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 1<<20 {
			t.Skip()
		}
		set, err := ParseRepositorySet(content)
		if err != nil {
			return
		}
		if len(set.Repositories) < 1 || len(set.Repositories) > 10000 || set.MaxConcurrency < 1 || set.MaxConcurrency > len(set.Repositories) {
			t.Fatalf("parser accepted an out-of-contract repository set: %#v", set)
		}
		document := RepositorySetDocument{
			APIVersion: RepositorySetAPIVersion,
			Kind:       RepositorySetKind,
			Schedule: RepositoryScheduleDocument{
				Interval: set.Interval.String(), MaxJitter: set.MaxJitter.String(), MaxConcurrency: set.MaxConcurrency,
				RepositoryTimeout: set.RepositoryTimeout.String(),
				Retry:             RetryPolicyDocument{MaxAttempts: set.Retry.MaxAttempts, InitialBackoff: set.Retry.InitialBackoff.String(), MaxBackoff: set.Retry.MaxBackoff.String()},
			},
			Repositories: set.Repositories,
		}
		if _, err := json.Marshal(document); err != nil {
			t.Fatalf("marshal accepted repository set: %v", err)
		}
	})
}
