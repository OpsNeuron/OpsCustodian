package scanner

import (
	"context"
	"sort"
	"time"

	"github.com/opscustodian/opscustodian/internal/correlation"
	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/effective"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/normalize"
	"github.com/opscustodian/opscustodian/internal/ownership"
	"github.com/opscustodian/opscustodian/internal/parsers"
)

type Options struct {
	Root        string
	Source      string
	Revision    string
	Generator   string
	MaxFileSize int64
	Parsers     []parsers.Parser
}

func Scan(ctx context.Context, opts Options) (model.AgentBOM, error) {
	artifacts, err := discovery.Discover(ctx, opts.Root, discovery.Options{MaxFileSize: opts.MaxFileSize})
	if err != nil {
		return model.AgentBOM{}, err
	}
	var assets []model.Asset
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
			assets = append(assets, parsed...)
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	bom := model.AgentBOM{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata: model.DocumentMetadata{
			Source: opts.Source, Revision: opts.Revision,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Generator:   opts.Generator, NormalizationVersion: "v1alpha1",
		},
		Assets: assets, Diagnostics: diagnostics,
	}
	bom.Diagnostics = append(bom.Diagnostics, ownership.ApplyCODEOWNERS(&bom, artifacts)...)
	normalize.BOM(&bom)
	effective.ComposeImports(&bom)
	normalize.BOM(&bom)
	correlation.Build(&bom)
	return bom, nil
}
