package ingestion

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type GitHubArchiveHTTPOptions struct {
	Endpoint            string
	AllowInsecure       bool
	Timeout             time.Duration
	Client              *http.Client
	Credentials         CredentialResolver
	AllowedArchiveHosts []string
	Materialization     GitHubArchiveOptions
}

type GitHubArchiveClient struct {
	endpoint        *url.URL
	allowInsecure   bool
	client          http.Client
	credentials     CredentialResolver
	allowedHosts    map[string]struct{}
	materialization GitHubArchiveOptions
}

func NewGitHubArchiveClient(options GitHubArchiveHTTPOptions) (*GitHubArchiveClient, error) {
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = defaultGitHubAPIEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("GitHub API endpoint must be an absolute URL without userinfo, query, or fragment")
	}
	if parsed.Scheme != "https" && !(options.AllowInsecure && parsed.Scheme == "http") {
		return nil, fmt.Errorf("GitHub API endpoint must use HTTPS")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultGitHubRequestTimeout
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("GitHub archive request timeout must be between 1ns and 1m")
	}
	client := http.Client{}
	if options.Client != nil {
		client = *options.Client
	}
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	allowedHosts := make(map[string]struct{})
	defaults := options.AllowedArchiveHosts
	if len(defaults) == 0 {
		if strings.EqualFold(parsed.Hostname(), "api.github.com") {
			defaults = []string{"codeload.github.com"}
		} else {
			defaults = []string{parsed.Hostname()}
		}
	}
	for _, host := range defaults {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/:@?#") {
			return nil, fmt.Errorf("GitHub archive host allowlist contains invalid host")
		}
		allowedHosts[host] = struct{}{}
	}
	if _, err := normalizeGitHubArchiveLimits(options.Materialization.Limits); err != nil {
		return nil, err
	}
	return &GitHubArchiveClient{
		endpoint: parsed, allowInsecure: options.AllowInsecure, client: client, credentials: options.Credentials,
		allowedHosts: allowedHosts, materialization: options.Materialization,
	}, nil
}

func (client *GitHubArchiveClient) Acquire(ctx context.Context, repository Repository, revision string) (*MaterializedCheckout, error) {
	if client == nil || client.endpoint == nil {
		return nil, fmt.Errorf("GitHub archive client is not initialized")
	}
	owner, name, err := ParseGitHubSource(repository.Source)
	if err != nil {
		return nil, err
	}
	if repository.Connector != GitHubConnectorName {
		return nil, fmt.Errorf("GitHub archive client received connector %q", repository.Connector)
	}
	revision, err = normalizeGitHubSHA(revision)
	if err != nil {
		return nil, err
	}
	token, err := resolveGitHubCredential(ctx, repository.CredentialReference, client.credentials)
	if err != nil {
		return nil, err
	}
	requestURL := *client.endpoint
	requestURL.Path = path.Join(client.endpoint.Path, "repos", owner, name, "zipball", revision)
	request, err := client.archiveRequest(ctx, requestURL.String(), token)
	if err != nil {
		return nil, err
	}
	response, err := client.do(request)
	if err != nil {
		return nil, err
	}
	if isGitHubRedirect(response.StatusCode) {
		location := response.Header.Get("Location")
		_ = response.Body.Close()
		target, err := client.validateArchiveRedirect(location)
		if err != nil {
			return nil, err
		}
		request, err = client.archiveRequest(ctx, target.String(), "")
		if err != nil {
			return nil, err
		}
		response, err = client.do(request)
		if err != nil {
			return nil, err
		}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("GitHub archive request returned status %d", response.StatusCode)
		if githubStatusTransient(response) {
			return nil, Transient(err)
		}
		return nil, err
	}
	return MaterializeGitHubZIP(ctx, response.Body, client.materialization)
}

func (client *GitHubArchiveClient) archiveRequest(ctx context.Context, target, token string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("create GitHub archive request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "OpsCustodian GitHub connector")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request, nil
}

func (client *GitHubArchiveClient) do(request *http.Request) (*http.Response, error) {
	response, err := client.client.Do(request)
	if err != nil {
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
		return nil, Transient(errors.New("GitHub archive request failed"))
	}
	return response, nil
}

func (client *GitHubArchiveClient) validateArchiveRedirect(location string) (*url.URL, error) {
	target, err := url.Parse(location)
	if err != nil || !target.IsAbs() || target.User != nil || target.Fragment != "" {
		return nil, fmt.Errorf("GitHub archive redirect target is invalid")
	}
	if target.Scheme != "https" && !(client.allowInsecure && target.Scheme == "http") {
		return nil, fmt.Errorf("GitHub archive redirect target must use HTTPS")
	}
	if _, allowed := client.allowedHosts[strings.ToLower(target.Hostname())]; !allowed {
		return nil, fmt.Errorf("GitHub archive redirect target is not allowlisted")
	}
	return target, nil
}

func isGitHubRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}
