package ingestion

import (
	"context"
	"errors"
	"testing"
)

type recordingCredentialResolver struct {
	token     string
	reference string
}

func (resolver *recordingCredentialResolver) Resolve(_ context.Context, reference string) (string, error) {
	resolver.reference = reference
	if resolver.token == "" {
		return "", errors.New("unavailable")
	}
	return resolver.token, nil
}

func TestGitHubCredentialRouterSelectsResolverWithoutFallback(t *testing.T) {
	environment := &recordingCredentialResolver{token: "environment-token"}
	app := &recordingCredentialResolver{token: "app-token"}
	router, err := NewGitHubCredentialRouter(environment, app)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := router.Resolve(context.Background(), "env:OPSCUSTODIAN_GITHUB_TOKEN_PLATFORM"); err != nil || token != "environment-token" || environment.reference == "" || app.reference != "" {
		t.Fatalf("environment route = %q, %v", token, err)
	}
	if token, err := router.Resolve(context.Background(), "github-app:installation:42"); err != nil || token != "app-token" || app.reference == "" {
		t.Fatalf("app route = %q, %v", token, err)
	}
}

func TestGitHubCredentialRouterFailsClosedWithoutAppResolver(t *testing.T) {
	environment := &recordingCredentialResolver{token: "environment-token"}
	router, _ := NewGitHubCredentialRouter(environment, nil)
	if _, err := router.Resolve(context.Background(), "github-app:installation:42"); err == nil || environment.reference != "" {
		t.Fatalf("app reference unexpectedly fell back: %v", err)
	}
}
