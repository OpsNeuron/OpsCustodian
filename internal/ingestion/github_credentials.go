package ingestion

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const githubTokenEnvironmentPrefix = "OPSCUSTODIAN_GITHUB_TOKEN_"

type EnvironmentLookup func(string) (string, bool)

type EnvironmentCredentialResolver struct {
	lookup EnvironmentLookup
}

func NewEnvironmentCredentialResolver(lookup EnvironmentLookup) (*EnvironmentCredentialResolver, error) {
	if lookup == nil {
		return nil, fmt.Errorf("credential environment lookup is required")
	}
	return &EnvironmentCredentialResolver{lookup: lookup}, nil
}

func (resolver *EnvironmentCredentialResolver) Resolve(ctx context.Context, reference string) (string, error) {
	if resolver == nil || resolver.lookup == nil {
		return "", errors.New("credential environment resolver is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	name, err := GitHubCredentialEnvironmentName(reference)
	if err != nil {
		return "", err
	}
	value, exists := resolver.lookup(name)
	if !exists || value == "" {
		return "", errors.New("GitHub credential environment value is unavailable")
	}
	return value, nil
}

func GitHubCredentialEnvironmentName(reference string) (string, error) {
	if !strings.HasPrefix(reference, "env:") {
		return "", fmt.Errorf("GitHub credential reference must use env:OPSCUSTODIAN_GITHUB_TOKEN_*")
	}
	name := strings.TrimPrefix(reference, "env:")
	if !strings.HasPrefix(name, githubTokenEnvironmentPrefix) || len(name) <= len(githubTokenEnvironmentPrefix) || len(name) > 128 {
		return "", fmt.Errorf("GitHub credential environment variable is outside the allowed namespace")
	}
	for _, character := range name {
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_') {
			return "", fmt.Errorf("GitHub credential environment variable name is invalid")
		}
	}
	return name, nil
}
