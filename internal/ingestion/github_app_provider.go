package ingestion

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const githubAppJWTLifetime = 9 * time.Minute

type GitHubAppProviderOptions struct {
	AppID         int64
	PrivateKeyPEM []byte
	Endpoint      string
	AllowInsecure bool
	Timeout       time.Duration
	Client        *http.Client
	Now           func() time.Time
	Observer      GitHubAuthObserver
}

type GitHubAppProvider struct {
	appID      int64
	privateKey *rsa.PrivateKey
	endpoint   *url.URL
	client     http.Client
	now        func() time.Time
	observer   GitHubAuthObserver
}

func NewGitHubAppProvider(options GitHubAppProviderOptions) (*GitHubAppProvider, error) {
	if options.AppID <= 0 {
		return nil, fmt.Errorf("GitHub App ID must be positive")
	}
	privateKey, err := parseGitHubAppPrivateKey(options.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("GitHub App request timeout must be between 1ns and 1m")
	}
	client := http.Client{}
	if options.Client != nil {
		client = *options.Client
	}
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &GitHubAppProvider{appID: options.AppID, privateKey: privateKey, endpoint: parsed, client: client, now: now, observer: options.Observer}, nil
}

func (provider *GitHubAppProvider) InstallationToken(ctx context.Context, installationID int64) (result GitHubAppInstallationToken, resultErr error) {
	if provider == nil || provider.privateKey == nil || provider.endpoint == nil || provider.now == nil {
		return GitHubAppInstallationToken{}, errors.New("GitHub App provider is not initialized")
	}
	startedAt := provider.now()
	observation := GitHubAuthObservation{OccurredAt: startedAt, Operation: GitHubAuthOperationTokenExchange, Result: GitHubAuthResultFailed}
	defer func() {
		observation.DurationMillis = max(provider.now().Sub(startedAt).Milliseconds(), 0)
		if provider.observer != nil {
			if err := provider.observer(ctx, observation); err != nil {
				result = GitHubAppInstallationToken{}
				resultErr = errors.New("GitHub authentication observation failed")
			}
		}
	}()
	if installationID <= 0 {
		return GitHubAppInstallationToken{}, errors.New("GitHub App installation ID must be positive")
	}
	jwt, err := provider.signJWT(provider.now())
	if err != nil {
		return GitHubAppInstallationToken{}, errors.New("sign GitHub App JWT")
	}
	requestURL := *provider.endpoint
	requestURL.Path = path.Join(provider.endpoint.Path, "app", "installations", fmt.Sprint(installationID), "access_tokens")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader([]byte("{}")))
	if err != nil {
		return GitHubAppInstallationToken{}, errors.New("create GitHub App token request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "OpsCustodian GitHub connector")
	request.Header.Set("Authorization", "Bearer "+jwt)

	response, err := provider.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			observation.Result = GitHubAuthResultCancelled
			return GitHubAppInstallationToken{}, ctx.Err()
		}
		observation.Transient = true
		return GitHubAppInstallationToken{}, Transient(errors.New("GitHub App token request failed"))
	}
	defer response.Body.Close()
	observation.HTTPStatus = response.StatusCode
	if response.StatusCode != http.StatusCreated {
		err := fmt.Errorf("GitHub App token request returned status %d", response.StatusCode)
		if githubStatusTransient(response) {
			observation.Transient = true
			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusForbidden {
				observation.Result = GitHubAuthResultRateLimited
			}
			return GitHubAppInstallationToken{}, Transient(err)
		}
		observation.Result = GitHubAuthResultRejected
		return GitHubAppInstallationToken{}, err
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumGitHubResponseBytes+1))
	if err != nil {
		return GitHubAppInstallationToken{}, errors.New("read GitHub App token response")
	}
	if len(content) > maximumGitHubResponseBytes {
		return GitHubAppInstallationToken{}, fmt.Errorf("GitHub App token response exceeds %d bytes", maximumGitHubResponseBytes)
	}
	var payload struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&payload); err != nil {
		return GitHubAppInstallationToken{}, errors.New("decode GitHub App token response")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return GitHubAppInstallationToken{}, errors.New("decode GitHub App token response")
	}
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return GitHubAppInstallationToken{}, errors.New("GitHub App token response contains invalid expiry")
	}
	token := GitHubAppInstallationToken{Value: payload.Token, ExpiresAt: expiresAt}
	if err := validateGitHubAppInstallationToken(token, provider.now(), 0); err != nil {
		return GitHubAppInstallationToken{}, errors.New("GitHub App token response is invalid")
	}
	observation.Result = GitHubAuthResultSucceeded
	return token, nil
}

func (provider *GitHubAppProvider) signJWT(now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, err := json.Marshal(struct {
		IssuedAt  int64 `json:"iat"`
		ExpiresAt int64 `json:"exp"`
		Issuer    int64 `json:"iss"`
	}{IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(githubAppJWTLifetime).Unix(), Issuer: provider.appID})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(rand.Reader, provider.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseGitHubAppPrivateKey(content []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(content)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("GitHub App private key must contain exactly one PEM block")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		err = parseErr
		if parseErr == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("private key is not RSA")
			}
		}
	default:
		return nil, fmt.Errorf("GitHub App private key PEM type is unsupported")
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("GitHub App private key must be a valid RSA key of at least 2048 bits")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("GitHub App private key is invalid")
	}
	return key, nil
}
