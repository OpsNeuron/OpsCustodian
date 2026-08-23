package ingestion

import (
	"context"
	"errors"
	"strings"
)

type GitHubCredentialRouter struct {
	environment CredentialResolver
	app         CredentialResolver
}

func NewGitHubCredentialRouter(environment, app CredentialResolver) (*GitHubCredentialRouter, error) {
	if environment == nil {
		return nil, errors.New("GitHub environment credential resolver is required")
	}
	return &GitHubCredentialRouter{environment: environment, app: app}, nil
}

func (router *GitHubCredentialRouter) Resolve(ctx context.Context, reference string) (string, error) {
	if router == nil || router.environment == nil {
		return "", errors.New("GitHub credential router is unavailable")
	}
	if strings.HasPrefix(reference, githubAppInstallationPrefix) {
		if router.app == nil {
			return "", errors.New("GitHub App authentication is not configured")
		}
		return router.app.Resolve(ctx, reference)
	}
	return router.environment.Resolve(ctx, reference)
}
