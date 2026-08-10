package scanner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/opscustodian/opscustodian/internal/boundary"
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
	Boundaries  []string
}

func Scan(ctx context.Context, opts Options) (model.AgentBOM, error) {
	if err := parsers.ValidateRegistry(opts.Parsers); err != nil {
		return model.AgentBOM{}, fmt.Errorf("invalid parser registry: %w", err)
	}
	artifacts, err := discovery.Discover(ctx, opts.Root, discovery.Options{MaxFileSize: opts.MaxFileSize})
	if err != nil {
		return model.AgentBOM{}, err
	}
	var assets []model.Asset
	assetIDs := map[string]struct{}{}
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
			validated, contractDiagnostics := parsers.ValidateResult(parser, artifact, parsed)
			diagnostics = append(diagnostics, contractDiagnostics...)
			for _, asset := range validated {
				if _, exists := assetIDs[asset.ID]; exists {
					diagnostics = append(diagnostics, model.Diagnostic{Severity: "error", Code: "duplicate-asset-id", Path: artifact.RelPath, Parser: parser.Name(), Message: "asset id is already emitted: " + asset.ID})
					continue
				}
				assetIDs[asset.ID] = struct{}{}
				assets = append(assets, asset)
			}
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
	bom.Diagnostics = append(bom.Diagnostics, ownership.ApplyBackstage(&bom, artifacts)...)
	bom.Diagnostics = append(bom.Diagnostics, ownership.ApplyCODEOWNERS(&bom, artifacts)...)
	definitions, err := boundary.Parse(opts.Boundaries)
	if err != nil {
		return model.AgentBOM{}, err
	}
	boundary.Apply(&bom, definitions)
	normalize.BOM(&bom)
	effective.ComposeImports(&bom)
	effective.ComposeKubernetesRBAC(&bom)
	normalize.BOM(&bom)
	correlation.Build(&bom)
	return bom, nil
}
