package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/normalize"
	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/parsers/agentmarkdown"
	"github.com/opscustodian/opscustodian/internal/parsers/ghaw"
	"github.com/opscustodian/opscustodian/internal/parsers/githubactions"
	"github.com/opscustodian/opscustodian/internal/parsers/kubernetes"
	"github.com/opscustodian/opscustodian/internal/parsers/mcp"
	"github.com/opscustodian/opscustodian/internal/policy"
	"github.com/opscustodian/opscustodian/internal/report"
	"github.com/opscustodian/opscustodian/internal/scanner"
	"github.com/opscustodian/opscustodian/internal/validation"
	"gopkg.in/yaml.v3"
)

type ScanOptions struct {
	Root, Output, Format string
	MaxFileSize          int64
	Boundaries           []string
}

type DiffOptions struct {
	Before, After, Format, FailOn, Output string
}

type ExplainOptions struct {
	Report, FindingID string
}

type CheckOptions struct {
	BOM, Baseline, Policy, OPA, Query, Format string
	Timeout                                   time.Duration
}

type EventsOptions struct {
	BOM, Drift, Output string
	OccurredAt         time.Time
	OTLPEndpoint       string
	OTLPHeaders        map[string]string
	OTLPTimeout        time.Duration
	AllowInsecureOTLP  bool
}

type InventoryReportOptions struct {
	BOM, Output string
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func Scan(ctx context.Context, opts ScanOptions) error {
	absRoot, err := filepath.Abs(opts.Root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}
	bom, err := scanner.Scan(ctx, scanner.Options{
		Root: absRoot, Source: filepath.ToSlash(absRoot), Revision: "working-tree",
		Generator: "opscustodian/dev", MaxFileSize: opts.MaxFileSize,
		Boundaries: opts.Boundaries,
		Parsers:    []parsers.Parser{githubactions.Parser{}, ghaw.Parser{}, mcp.Parser{}, agentmarkdown.Parser{}, kubernetes.Parser{}},
	})
	if err != nil {
		return err
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return fmt.Errorf("generated Agent BOM failed validation: %s", formatValidationIssues(issues))
	}
	w, closeWriter, err := outputWriter(opts.Output)
	if err != nil {
		return err
	}
	defer closeWriter()
	return report.WriteBOM(w, bom, opts.Format)
}

func Diff(opts DiffOptions) error {
	if opts.FailOn != "" && severityRank(opts.FailOn) == 0 {
		return fmt.Errorf("unsupported fail-on severity %q; expected info, low, medium, high, or critical", opts.FailOn)
	}
	before, err := readBOM(opts.Before)
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	after, err := readBOM(opts.After)
	if err != nil {
		return fmt.Errorf("read proposed BOM: %w", err)
	}
	value := drift.Compare(before, after)
	w, closeWriter, err := outputWriter(opts.Output)
	if err != nil {
		return err
	}
	defer closeWriter()
	if err := report.WriteDiff(w, value, opts.Format); err != nil {
		return err
	}
	if threshold := severityRank(opts.FailOn); threshold > 0 {
		for _, change := range value.Changes {
			if severityRank(change.Severity) >= threshold {
				return &ExitError{Code: 2, Err: fmt.Errorf("semantic drift reached %s threshold", opts.FailOn)}
			}
		}
	}
	return nil
}

func Events(opts EventsOptions) error {
	if (opts.BOM == "") == (opts.Drift == "") {
		return fmt.Errorf("exactly one of --bom or --drift is required")
	}
	when := opts.OccurredAt
	if when.IsZero() {
		when = time.Now().UTC()
	}
	var events []audit.Event
	if opts.BOM != "" {
		bom, err := readBOM(opts.BOM)
		if err != nil {
			return fmt.Errorf("read Agent BOM: %w", err)
		}
		events = audit.FromBOM(bom, when)
	} else {
		content, err := os.ReadFile(opts.Drift)
		if err != nil {
			return fmt.Errorf("read drift report: %w", err)
		}
		var value drift.Report
		if err := json.Unmarshal(content, &value); err != nil {
			return fmt.Errorf("parse drift report: %w", err)
		}
		events = audit.FromDrift(value, when)
	}
	w, closeWriter, err := outputWriter(opts.Output)
	if err != nil {
		return err
	}
	if err := audit.WriteJSONLines(w, events); err != nil {
		closeWriter()
		return err
	}
	closeWriter()
	if opts.OTLPEndpoint != "" {
		return audit.ExportOTLPHTTP(context.Background(), events, audit.OTLPHTTPOptions{
			Endpoint: opts.OTLPEndpoint, Headers: opts.OTLPHeaders, Timeout: opts.OTLPTimeout,
			AllowInsecure: opts.AllowInsecureOTLP, ObservedAt: when,
		})
	}
	return nil
}

func Explain(opts ExplainOptions) error {
	content, err := os.ReadFile(opts.Report)
	if err != nil {
		return fmt.Errorf("read drift report: %w", err)
	}
	var value drift.Report
	if err := json.Unmarshal(content, &value); err != nil {
		return fmt.Errorf("parse drift report: %w", err)
	}
	change, exists := drift.Find(value, opts.FindingID)
	if !exists {
		return fmt.Errorf("finding %q was not found", opts.FindingID)
	}
	return report.WriteExplanation(os.Stdout, change)
}

func Check(ctx context.Context, opts CheckOptions) error {
	bom, err := readBOM(opts.BOM)
	if err != nil {
		return fmt.Errorf("read Agent BOM: %w", err)
	}
	input := policy.Input{APIVersion: policy.InputAPIVersion, BOM: bom}
	if opts.Baseline != "" {
		baseline, err := readBOM(opts.Baseline)
		if err != nil {
			return fmt.Errorf("read baseline Agent BOM: %w", err)
		}
		value := drift.Compare(baseline, bom)
		input.Drift = &value
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	evaluationContext, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	decision, err := policy.EvaluateOPA(evaluationContext, input, policy.OPAOptions{
		BinaryPath: opts.OPA, PolicyPath: opts.Policy, Query: opts.Query,
	})
	if err != nil {
		return err
	}
	if err := report.WritePolicyDecision(os.Stdout, decision, opts.Format); err != nil {
		return err
	}
	if len(decision.Deny) > 0 {
		return &ExitError{Code: 2, Err: fmt.Errorf("policy denied %d finding(s)", len(decision.Deny))}
	}
	return nil
}

func InventoryReport(opts InventoryReportOptions) error {
	bom, err := readBOM(opts.BOM)
	if err != nil {
		return fmt.Errorf("read Agent BOM: %w", err)
	}
	w, closeWriter, err := outputWriter(opts.Output)
	if err != nil {
		return err
	}
	defer closeWriter()
	if err := report.WriteInventoryHTML(w, bom); err != nil {
		return fmt.Errorf("render inventory report: %w", err)
	}
	return nil
}

func readBOM(path string) (model.AgentBOM, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return model.AgentBOM{}, err
	}
	var bom model.AgentBOM
	if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		err = yaml.Unmarshal(content, &bom)
	} else {
		err = json.Unmarshal(content, &bom)
	}
	if err != nil {
		return model.AgentBOM{}, err
	}
	migrateLegacyBOM(&bom)
	normalize.BOM(&bom)
	if bom.APIVersion != model.APIVersion || bom.Kind != model.Kind {
		return model.AgentBOM{}, fmt.Errorf("unsupported document %s %s", bom.APIVersion, bom.Kind)
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		return model.AgentBOM{}, fmt.Errorf("invalid Agent BOM: %s", formatValidationIssues(issues))
	}
	return bom, nil
}

func migrateLegacyBOM(bom *model.AgentBOM) {
	if len(bom.Assets) == 0 && len(bom.LegacyAgents) > 0 {
		bom.Assets = bom.LegacyAgents
		bom.LegacyAgents = nil
	}
	for index := range bom.Assets {
		if len(bom.Assets[index].Owners) == 0 && bom.Assets[index].LegacyOwner != "" {
			bom.Assets[index].Owners = []string{bom.Assets[index].LegacyOwner}
			bom.Assets[index].LegacyOwner = ""
		}
		if bom.Assets[index].Type != "" {
			continue
		}
		runtimeType := ""
		if bom.Assets[index].Runtime != nil {
			runtimeType = bom.Assets[index].Runtime.Type
		}
		switch runtimeType {
		case "mcp-server":
			bom.Assets[index].Type = "mcp-server"
		case "github-actions":
			bom.Assets[index].Type = "workflow"
		default:
			bom.Assets[index].Type = "agent"
		}
	}
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
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("create output: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}
