package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/parsers/githubactions"
	"github.com/opscustodian/opscustodian/internal/parsers/mcp"
	"github.com/opscustodian/opscustodian/internal/report"
	"github.com/opscustodian/opscustodian/internal/scanner"
	"github.com/opscustodian/opscustodian/internal/validation"
	"gopkg.in/yaml.v3"
)

type ScanOptions struct {
	Root, Output, Format string
	MaxFileSize          int64
}

type DiffOptions struct {
	Before, After, Format, FailOn string
}

type ExplainOptions struct {
	Report, FindingID string
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func Scan(ctx context.Context, opts ScanOptions) error {
	absRoot, err := filepath.Abs(opts.Root)
	if err != nil { return fmt.Errorf("resolve root: %w", err) }
	bom, err := scanner.Scan(ctx, scanner.Options{
		Root: absRoot, Source: filepath.ToSlash(absRoot), Revision: "working-tree",
		Generator: "opscustodian/dev", MaxFileSize: opts.MaxFileSize,
		Parsers: []parsers.Parser{githubactions.Parser{}, mcp.Parser{}},
	})
	if err != nil { return err }
	if issues := validation.Validate(bom); len(issues) > 0 {
		return fmt.Errorf("generated Agent BOM failed validation: %s", formatValidationIssues(issues))
	}
	w, closeWriter, err := outputWriter(opts.Output)
	if err != nil { return err }
	defer closeWriter()
	return report.WriteBOM(w, bom, opts.Format)
}

func Diff(opts DiffOptions) error {
	before, err := readBOM(opts.Before)
	if err != nil { return fmt.Errorf("read baseline: %w", err) }
	after, err := readBOM(opts.After)
	if err != nil { return fmt.Errorf("read proposed BOM: %w", err) }
	value := drift.Compare(before, after)
	if err := report.WriteDiff(os.Stdout, value, opts.Format); err != nil { return err }
	if threshold := severityRank(opts.FailOn); threshold > 0 {
		for _, change := range value.Changes {
			if severityRank(change.Severity) >= threshold {
				return &ExitError{Code: 2, Err: fmt.Errorf("semantic drift reached %s threshold", opts.FailOn)}
			}
		}
	}
	return nil
}

func Explain(opts ExplainOptions) error {
	content, err := os.ReadFile(opts.Report)
	if err != nil { return fmt.Errorf("read drift report: %w", err) }
	var value drift.Report
	if err := json.Unmarshal(content, &value); err != nil { return fmt.Errorf("parse drift report: %w", err) }
	change, exists := drift.Find(value, opts.FindingID)
	if !exists { return fmt.Errorf("finding %q was not found", opts.FindingID) }
	return report.WriteExplanation(os.Stdout, change)
}

func readBOM(path string) (model.AgentBOM, error) {
	content, err := os.ReadFile(path)
	if err != nil { return model.AgentBOM{}, err }
	var bom model.AgentBOM
	if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		err = yaml.Unmarshal(content, &bom)
	} else {
		err = json.Unmarshal(content, &bom)
	}
	if err != nil { return model.AgentBOM{}, err }
	if bom.APIVersion != model.APIVersion || bom.Kind != model.Kind {
		return model.AgentBOM{}, fmt.Errorf("unsupported document %s %s", bom.APIVersion, bom.Kind)
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return model.AgentBOM{}, fmt.Errorf("invalid Agent BOM: %s", formatValidationIssues(issues))
	}
	return bom, nil
}

func formatValidationIssues(issues []validation.Issue) string {
	parts := make([]string, 0, len(issues))
	for _, issue := range issues {
		parts = append(parts, issue.Path+": "+issue.Message)
	}
	return strings.Join(parts, "; ")
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical": return 5
	case "high": return 4
	case "medium": return 3
	case "low": return 2
	case "info": return 1
	default: return 0
	}
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil { return nil, func() {}, fmt.Errorf("create output: %w", err) }
	return file, func() { _ = file.Close() }, nil
}
