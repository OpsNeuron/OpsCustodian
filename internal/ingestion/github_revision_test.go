package ingestion

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const githubTestToken = "github-test-token-0123456789abcdefghijkl"

func TestGitHubRevisionClientResolvesCommitWithoutLeakingCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/acme/platform/commits/main" || request.Header.Get("Authorization") != "Bearer "+githubTestToken || request.Header.Get("X-GitHub-Api-Version") == "" {
			t.Fatalf("request = %s, headers = %#v", request.URL.Path, request.Header)
		}
		_, _ = response.Write([]byte(`{"sha":"0123456789abcdef0123456789abcdef01234567","ignored":"safe"}`))
	}))
	defer server.Close()
	client, err := NewGitHubRevisionClient(GitHubRevisionOptions{Endpoint: server.URL, AllowInsecure: true, Client: server.Client(), Credentials: staticCredentialResolver{token: githubTestToken}})
	if err != nil {
		t.Fatal(err)
	}
	sha, err := client.Resolve(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main", CredentialReference: "env:GITHUB_TOKEN"})
	if err != nil || sha != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("sha = %q, err = %v", sha, err)
	}
}

func TestGitHubRevisionClientClassifiesRetryableStatus(t *testing.T) {
	for name, status := range map[string]int{"rate limit": http.StatusTooManyRequests, "server": http.StatusInternalServerError} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(status) }))
			defer server.Close()
			client, _ := NewGitHubRevisionClient(GitHubRevisionOptions{Endpoint: server.URL, AllowInsecure: true, Client: server.Client()})
			_, err := client.Resolve(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main"})
			if err == nil || !isTransient(err) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestGitHubRevisionClientRejectsRedirectAndUnsafeResponses(t *testing.T) {
	redirectFollowed := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectFollowed = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client, _ := NewGitHubRevisionClient(GitHubRevisionOptions{Endpoint: redirect.URL, AllowInsecure: true, Client: redirect.Client()})
	_, err := client.Resolve(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main"})
	if err == nil || redirectFollowed || strings.Contains(err.Error(), target.URL) {
		t.Fatalf("redirect error = %v, followed = %v", err, redirectFollowed)
	}

	for name, payload := range map[string]string{
		"malformed": `{"sha":"not-a-sha"}`,
		"oversized": `{"sha":"0123456789abcdef0123456789abcdef01234567","padding":"` + strings.Repeat("x", maximumGitHubResponseBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write([]byte(payload)) }))
			defer server.Close()
			client, _ := NewGitHubRevisionClient(GitHubRevisionOptions{Endpoint: server.URL, AllowInsecure: true, Client: server.Client()})
			if _, err := client.Resolve(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main"}); err == nil {
				t.Fatal("unsafe response was accepted")
			}
		})
	}
}

func TestGitHubRevisionClientProtectsEndpointSourceAndCredentialErrors(t *testing.T) {
	if _, err := NewGitHubRevisionClient(GitHubRevisionOptions{Endpoint: "http://api.github.test"}); err == nil {
		t.Fatal("insecure endpoint was accepted")
	}
	client, err := NewGitHubRevisionClient(GitHubRevisionOptions{Credentials: staticCredentialResolver{err: errors.New("secret backend detail")}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Resolve(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main", CredentialReference: "vault:github"})
	if err == nil || strings.Contains(err.Error(), "secret backend detail") {
		t.Fatalf("credential error = %v", err)
	}
	for _, source := range []string{"github:acme", "gitlab:acme/platform", "github:acme/platform/extra", "github:acme/plat form"} {
		if _, _, err := ParseGitHubSource(source); err == nil {
			t.Fatalf("invalid source %q was accepted", source)
		}
	}
}

type staticCredentialResolver struct {
	token string
	err   error
}

func (resolver staticCredentialResolver) Resolve(context.Context, string) (string, error) {
	return resolver.token, resolver.err
}
