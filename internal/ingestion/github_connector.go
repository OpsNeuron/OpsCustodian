package ingestion

import (
	"context"
	"errors"
	"fmt"

	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/scanner"
)

type GitHubRevisionResolver interface {
	Resolve(context.Context, Repository) (string, error)
}

type GitHubArchiveAcquirer interface {
	Acquire(context.Context, Repository, string) (*MaterializedCheckout, error)
}

type GitHubConnector struct {
	Revisions GitHubRevisionResolver
	Archives  GitHubArchiveAcquirer
	Parsers   []parsers.Parser
}

func NewGitHubConnector(revisions GitHubRevisionResolver, archives GitHubArchiveAcquirer) (*GitHubConnector, error) {
	if revisions == nil || archives == nil {
		return nil, fmt.Errorf("GitHub revision and archive clients are required")
	}
	return &GitHubConnector{Revisions: revisions, Archives: archives, Parsers: defaultIngestionParsers()}, nil
}

func (*GitHubConnector) Name() string { return GitHubConnectorName }

func (connector *GitHubConnector) Fetch(ctx context.Context, repository Repository, knownRevision string) (result FetchResult, resultErr error) {
	if connector == nil || connector.Revisions == nil || connector.Archives == nil || len(connector.Parsers) == 0 {
		return FetchResult{}, fmt.Errorf("GitHub connector is not initialized")
	}
	if repository.Connector != GitHubConnectorName {
		return FetchResult{}, fmt.Errorf("GitHub connector received repository type %q", repository.Connector)
	}
	if _, _, err := ParseGitHubSource(repository.Source); err != nil {
		return FetchResult{}, err
	}
	if err := validateGitHubRef(repository.Ref); err != nil {
		return FetchResult{}, err
	}
	revision, err := connector.Revisions.Resolve(ctx, repository)
	if err != nil {
		return FetchResult{}, err
	}
	revision, err = normalizeGitHubSHA(revision)
	if err != nil {
		return FetchResult{}, err
	}
	if knownRevision == revision {
		return FetchResult{Unchanged: true}, nil
	}
	checkout, err := connector.Archives.Acquire(ctx, repository, revision)
	if err != nil {
		return FetchResult{}, err
	}
	if checkout == nil || checkout.Root == "" {
		incomplete := errors.New("GitHub archive acquisition returned incomplete checkout")
		if checkout != nil {
			if err := checkout.Close(); err != nil {
				return FetchResult{}, errors.Join(incomplete, fmt.Errorf("cleanup GitHub checkout: %w", err))
			}
		}
		return FetchResult{}, incomplete
	}
	defer func() {
		if err := checkout.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cleanup GitHub checkout: %w", err))
			if resultErr != nil {
				result = FetchResult{}
			}
		}
	}()
	bom, err := scanner.Scan(ctx, scanner.Options{
		Root: checkout.Root, Source: repository.Source, Revision: revision,
		Generator: "opscustodian/github-connector", MaxFileSize: repository.MaxFileSize,
		Boundaries: append([]string(nil), repository.Boundaries...), Parsers: append([]parsers.Parser(nil), connector.Parsers...),
	})
	if err != nil {
		return FetchResult{}, err
	}
	bom.Metadata.GeneratedAt = ""
	return FetchResult{BOM: bom}, nil
}
