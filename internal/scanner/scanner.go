package scanner

import (
	"context"
	"sort"
	"time"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/parsers"
)

type Options struct {
	Root         string
	Source       string
	Revision     string
	Generator    string
	MaxFileSize  int64
	Parsers      []parsers.Parser
}

func Scan(ctx context.Context, opts Options) (model.AgentBOM, error) {
	artifacts, err := discovery.Discover(ctx, opts.Root, discovery.Options{MaxFileSize: opts.MaxFileSize})
	if err != nil {
		return model.AgentBOM{}, err
	}
	var agents []model.Agent
	var diagnostics []model.Diagnostic
	for _, artifact := range artifacts {
		for _, parser := range opts.Parsers {
			if !parser.Supports(artifact) {
				continue
			}
			parsed, err := parser.Parse(ctx, artifact)
			if err != nil {
				diagnostics = append(diagnostics, model.Diagnostic{
					Severity: "error", Code: "artifact-parse-failed", Path: artifact.RelPath,
					Parser: parser.Name(), Message: err.Error(),
				})
				continue
			}
			agents = append(agents, parsed...)
		}
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })
	return model.AgentBOM{
		APIVersion: model.APIVersion,
		Kind: model.Kind,
		Metadata: model.DocumentMetadata{
			Source: opts.Source, Revision: opts.Revision,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Generator: opts.Generator, NormalizationVersion: "v1alpha1",
		},
		Agents: agents, Diagnostics: diagnostics,
	}, nil
}
