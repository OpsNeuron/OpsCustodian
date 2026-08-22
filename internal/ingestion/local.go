package ingestion

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/parsers/agentmarkdown"
	"github.com/opscustodian/opscustodian/internal/parsers/ghaw"
	"github.com/opscustodian/opscustodian/internal/parsers/githubactions"
	"github.com/opscustodian/opscustodian/internal/parsers/kubernetes"
	"github.com/opscustodian/opscustodian/internal/parsers/mcp"
	"github.com/opscustodian/opscustodian/internal/scanner"
)

const LocalConnectorName = "local"

type LocalConnector struct {
	Parsers []parsers.Parser
}

func NewLocalConnector() LocalConnector {
	return LocalConnector{Parsers: defaultIngestionParsers()}
}

func defaultIngestionParsers() []parsers.Parser {
	return []parsers.Parser{githubactions.Parser{}, ghaw.Parser{}, mcp.Parser{}, agentmarkdown.Parser{}, kubernetes.Parser{}}
}

func (LocalConnector) Name() string { return LocalConnectorName }

func (connector LocalConnector) Fetch(ctx context.Context, repository Repository, knownRevision string) (FetchResult, error) {
	if strings.TrimSpace(repository.Source) == "" || strings.TrimSpace(repository.Revision) == "" {
		return FetchResult{}, fmt.Errorf("local repository source and revision are required")
	}
	if repository.Connector != LocalConnectorName {
		return FetchResult{}, fmt.Errorf("local connector received repository type %q", repository.Connector)
	}
	if !filepath.IsAbs(repository.Location) || filepath.Clean(repository.Location) != repository.Location {
		return FetchResult{}, fmt.Errorf("local repository location must be a clean absolute path")
	}
	info, err := os.Stat(repository.Location)
	if err != nil {
		return FetchResult{}, fmt.Errorf("inspect local repository: %w", err)
	}
	if !info.IsDir() {
		return FetchResult{}, fmt.Errorf("local repository location must be a directory")
	}
	if knownRevision == repository.Revision {
		return FetchResult{Unchanged: true}, nil
	}
	if len(connector.Parsers) == 0 {
		return FetchResult{}, fmt.Errorf("local connector parser registry is required")
	}
	bom, err := scanner.Scan(ctx, scanner.Options{
		Root: repository.Location, Source: repository.Source, Revision: repository.Revision,
		Generator: "opscustodian/local-connector", MaxFileSize: repository.MaxFileSize,
		Boundaries: append([]string(nil), repository.Boundaries...), Parsers: append([]parsers.Parser(nil), connector.Parsers...),
	})
	if err != nil {
		return FetchResult{}, err
	}
	// Execution time belongs to scheduler/audit observations. Keeping it out of
	// immutable repository content makes the same source/revision reproducible.
	bom.Metadata.GeneratedAt = ""
	return FetchResult{BOM: bom}, nil
}
