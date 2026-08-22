package ingestion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubArchiveClientFollowsOneAllowlistedRedirectWithoutCredential(t *testing.T) {
	archive := githubTestZIP(t, map[string]githubZIPEntry{"root/workflow.yml": {content: "name: safe"}})
	codeload := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.URL.Query().Get("signature") != "safe" {
			t.Fatalf("codeload headers = %#v, query = %q", request.Header, request.URL.RawQuery)
		}
		_, _ = response.Write(archive)
	}))
	defer codeload.Close()
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+githubTestToken || !strings.Contains(request.URL.Path, "/zipball/") {
			t.Fatalf("API request = %s, headers = %#v", request.URL.Path, request.Header)
		}
		response.Header().Set("Location", codeload.URL+"/archive.zip?signature=safe")
		response.WriteHeader(http.StatusFound)
	}))
	defer api.Close()
	target, _ := url.Parse(codeload.URL)
	client, err := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{
		Endpoint: api.URL, AllowInsecure: true, Client: api.Client(), Credentials: staticCredentialResolver{token: githubTestToken},
		AllowedArchiveHosts: []string{target.Hostname()}, Materialization: GitHubArchiveOptions{TemporaryDirectory: t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkout, err := client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, CredentialReference: "env:GITHUB_TOKEN"}, "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	defer checkout.Close()
	content, err := os.ReadFile(filepath.Join(checkout.Root, "workflow.yml"))
	if err != nil || string(content) != "name: safe" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
}

func TestGitHubArchiveClientRejectsUnallowlistedAndChainedRedirects(t *testing.T) {
	called := false
	hostile := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer hostile.Close()
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", hostile.URL+"/signed?token=secret")
		response.WriteHeader(http.StatusFound)
	}))
	defer api.Close()
	client, err := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{
		Endpoint: strings.Replace(api.URL, "127.0.0.1", "localhost", 1), AllowInsecure: true, Client: api.Client(),
		AllowedArchiveHosts: []string{"localhost"}, Materialization: GitHubArchiveOptions{TemporaryDirectory: t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName}, "0123456789abcdef0123456789abcdef01234567")
	if err == nil || called || strings.Contains(err.Error(), "token=secret") {
		t.Fatalf("redirect error = %v, called = %v", err, called)
	}

	secondRedirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "https://example.invalid/another", http.StatusFound)
	}))
	defer secondRedirect.Close()
	target, _ := url.Parse(secondRedirect.URL)
	chainAPI := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", secondRedirect.URL)
		response.WriteHeader(http.StatusFound)
	}))
	defer chainAPI.Close()
	client, _ = NewGitHubArchiveClient(GitHubArchiveHTTPOptions{
		Endpoint: chainAPI.URL, AllowInsecure: true, Client: chainAPI.Client(), AllowedArchiveHosts: []string{target.Hostname()},
		Materialization: GitHubArchiveOptions{TemporaryDirectory: t.TempDir()},
	})
	if _, err := client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName}, "0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Fatal("second redirect was accepted")
	}
}

func TestGitHubArchiveClientSupportsDirectArchiveAndClassifiesRateLimit(t *testing.T) {
	archive := githubTestZIP(t, map[string]githubZIPEntry{"root/file": {content: "safe"}})
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = response.Write(archive)
		}
	}))
	defer server.Close()
	client, _ := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{Endpoint: server.URL, AllowInsecure: true, Client: server.Client(), Materialization: GitHubArchiveOptions{TemporaryDirectory: t.TempDir()}})
	checkout, err := client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName}, "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	_ = checkout.Close()
	status = http.StatusTooManyRequests
	if _, err := client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName}, "0123456789abcdef0123456789abcdef01234567"); err == nil || !isTransient(err) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestGitHubArchiveClientValidatesEndpointAllowlistAndRevision(t *testing.T) {
	if _, err := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{Endpoint: "http://api.github.test"}); err == nil {
		t.Fatal("insecure endpoint was accepted")
	}
	if _, err := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{AllowedArchiveHosts: []string{"bad/host"}}); err == nil {
		t.Fatal("unsafe allowlist was accepted")
	}
	client, _ := NewGitHubArchiveClient(GitHubArchiveHTTPOptions{})
	if _, err := client.Acquire(context.Background(), Repository{Source: "github:acme/platform", Connector: GitHubConnectorName}, "branch-name"); err == nil {
		t.Fatal("mutable archive revision was accepted")
	}
}
