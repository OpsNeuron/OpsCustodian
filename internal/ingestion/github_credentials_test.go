package ingestion

import (
	"context"
	"strings"
	"testing"
)

func TestEnvironmentCredentialResolverAllowsOnlyGitHubTokenNamespace(t *testing.T) {
	resolver, err := NewEnvironmentCredentialResolver(func(name string) (string, bool) {
		if name != "OPSCUSTODIAN_GITHUB_TOKEN_PLATFORM" {
			t.Fatalf("environment name = %q", name)
		}
		return githubTestToken, true
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := resolver.Resolve(context.Background(), "env:OPSCUSTODIAN_GITHUB_TOKEN_PLATFORM")
	if err != nil || token != githubTestToken {
		t.Fatalf("token resolved = %v, err = %v", token == githubTestToken, err)
	}
	for _, reference := range []string{"env:OPSCUSTODIAN_DATABASE_DSN", "env:PATH", "vault:github", "env:OPSCUSTODIAN_GITHUB_TOKEN_bad"} {
		if _, err := resolver.Resolve(context.Background(), reference); err == nil {
			t.Fatalf("unsafe reference %q was accepted", reference)
		}
	}
}

func TestEnvironmentCredentialResolverDoesNotExposeMissingReferenceValue(t *testing.T) {
	resolver, _ := NewEnvironmentCredentialResolver(func(string) (string, bool) { return "", false })
	_, err := resolver.Resolve(context.Background(), "env:OPSCUSTODIAN_GITHUB_TOKEN_PRIVATE")
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("missing credential error = %v", err)
	}
}
