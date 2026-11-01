package server

import (
	"fmt"
	"testing"
	"time"
)

var (
	benchmarkIdentity string
	benchmarkMatched  bool
)

func BenchmarkBearerAuthentication(b *testing.B) {
	for _, count := range []int{1, 10, 100} {
		credentials := benchmarkCredentials(count)
		authenticator, _, err := newBearerCredentialSecurity(credentials, func() time.Time {
			return time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
		})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("credentials-%03d/hit-last", count), func(b *testing.B) {
			headers := []string{"Bearer " + credentials[len(credentials)-1].Token}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkIdentity, benchmarkMatched = authenticator.authenticate(headers)
			}
			if !benchmarkMatched || benchmarkIdentity != credentials[len(credentials)-1].ID {
				b.Fatal("benchmark credential did not authenticate")
			}
		})
		b.Run(fmt.Sprintf("credentials-%03d/miss", count), func(b *testing.B) {
			headers := []string{"Bearer benchmark-missing-token-abcdefghijklmnopqrstuvwxyz0123456789"}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkIdentity, benchmarkMatched = authenticator.authenticate(headers)
			}
			if benchmarkMatched || benchmarkIdentity != "" {
				b.Fatal("unknown benchmark credential authenticated")
			}
		})
	}
}

func BenchmarkCredentialRegistryReload(b *testing.B) {
	for _, count := range []int{1, 10, 100} {
		credentials := benchmarkCredentials(count)
		registry, err := newCredentialRegistry(credentials, func() time.Time {
			return time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
		})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("credentials-%03d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := registry.Reload(credentials); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkCredentials(count int) []BearerCredential {
	credentials := make([]BearerCredential, 0, count)
	for index := 0; index < count; index++ {
		credentials = append(credentials, BearerCredential{
			ID:           fmt.Sprintf("credential-%03d", index),
			Token:        fmt.Sprintf("benchmark-token-%03d-abcdefghijklmnopqrstuvwxyz0123456789", index),
			Scopes:       []string{ScopeInventoryRead, ScopeFindingsRead},
			Repositories: []string{fmt.Sprintf("repository-%016x", index)},
		})
	}
	return credentials
}
