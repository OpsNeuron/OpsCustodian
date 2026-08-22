package ingestion

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
)

const (
	GitHubConnectorName         = "github"
	defaultGitHubAPIEndpoint    = "https://api.github.com"
	maximumGitHubResponseBytes  = 1 << 20
	defaultGitHubRequestTimeout = 30 * time.Second
)

type CredentialResolver interface {
	Resolve(context.Context, string) (string, error)
}

type GitHubRevisionOptions struct {
	Endpoint      string
	AllowInsecure bool
	Timeout       time.Duration
	Client        *http.Client
	Credentials   CredentialResolver
}

type GitHubRevisionClient struct {
	endpoint    *url.URL
	client      http.Client
	credentials CredentialResolver
}

func NewGitHubRevisionClient(options GitHubRevisionOptions) (*GitHubRevisionClient, error) {
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
		return nil, fmt.Errorf("GitHub request timeout must be between 1ns and 1m")
	}
	client := http.Client{}
	if options.Client != nil {
		client = *options.Client
	}
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &GitHubRevisionClient{endpoint: parsed, client: client, credentials: options.Credentials}, nil
}

func (client *GitHubRevisionClient) Resolve(ctx context.Context, repository Repository) (string, error) {
	if client == nil || client.endpoint == nil {
		return "", fmt.Errorf("GitHub revision client is not initialized")
	}
	owner, name, err := ParseGitHubSource(repository.Source)
	if err != nil {
		return "", err
	}
	if repository.Connector != GitHubConnectorName {
		return "", fmt.Errorf("GitHub revision client received connector %q", repository.Connector)
	}
	if err := validateGitHubRef(repository.Ref); err != nil {
		return "", err
	}
	token := ""
	if repository.CredentialReference != "" {
		if err := validateSafeString(repository.CredentialReference, 256); err != nil || client.credentials == nil {
			return "", fmt.Errorf("GitHub credential reference is invalid or unavailable")
		}
		token, err = client.credentials.Resolve(ctx, repository.CredentialReference)
		if err != nil {
			message := errors.New("GitHub credential resolution failed")
			if isTransient(err) {
				return "", Transient(message)
			}
			return "", message
		}
		if err := validateGitHubToken(token); err != nil {
			return "", fmt.Errorf("resolved GitHub credential is invalid")
		}
	}

	requestURL := *client.endpoint
	requestURL.Path = path.Join(client.endpoint.Path, "repos", owner, name, "commits", repository.Ref)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create GitHub revision request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "OpsCustodian GitHub connector")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", Transient(fmt.Errorf("GitHub revision request failed: %w", err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("GitHub revision request returned status %d", response.StatusCode)
		if githubStatusTransient(response) {
			return "", Transient(err)
		}
		return "", err
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumGitHubResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read GitHub revision response")
	}
	if len(content) > maximumGitHubResponseBytes {
		return "", fmt.Errorf("GitHub revision response exceeds %d bytes", maximumGitHubResponseBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return "", fmt.Errorf("decode GitHub revision response")
	}
	sha, err := normalizeGitHubSHA(payload.SHA)
	if err != nil {
		return "", err
	}
	return sha, nil
}

func ParseGitHubSource(source string) (string, string, error) {
	value := strings.TrimPrefix(source, "github:")
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !validGitHubName(parts[0], 100) || !validGitHubName(parts[1], 100) {
		return "", "", fmt.Errorf("GitHub source must use github:owner/repository")
	}
	return parts[0], parts[1], nil
}

func validGitHubName(value string, maximum int) bool {
	if value == "" || value == "." || value == ".." || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validateGitHubRef(ref string) error {
	if err := validateSafeString(ref, 1024); err != nil || strings.Contains(ref, "..") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return fmt.Errorf("GitHub ref is invalid")
	}
	return nil
}

func validateGitHubToken(token string) error {
	if token == "" || strings.TrimSpace(token) != token {
		return fmt.Errorf("empty or untrimmed token")
	}
	for _, character := range token {
		if unicode.IsControl(character) {
			return fmt.Errorf("token contains control characters")
		}
	}
	return nil
}

func normalizeGitHubSHA(value string) (string, error) {
	if len(value) != 40 && len(value) != 64 {
		return "", fmt.Errorf("GitHub revision response contains invalid commit SHA")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("GitHub revision response contains invalid commit SHA")
	}
	return strings.ToLower(value), nil
}

func githubStatusTransient(response *http.Response) bool {
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return true
	}
	return response.StatusCode == http.StatusForbidden && (response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("Retry-After") != "")
}
