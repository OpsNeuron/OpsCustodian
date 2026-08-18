package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/opscustodian/opscustodian/internal/app"
	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/contracts"
)

var version = "dev"

type stringListFlag []string

func (values *stringListFlag) String() string         { return fmt.Sprint([]string(*values)) }
func (values *stringListFlag) Set(value string) error { *values = append(*values, value); return nil }

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var exitErr *app.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		output := fs.String("output", "-", "output file, or - for stdout")
		format := fs.String("format", "json", "output format: json or yaml")
		maxFileSize := fs.Int64("max-file-size", 2<<20, "maximum artifact size in bytes")
		var boundaries stringListFlag
		fs.Var(&boundaries, "boundary", "monorepo boundary path or path=component; repeatable")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		root := "."
		if fs.NArg() > 0 {
			root = fs.Arg(0)
		}
		return app.Scan(ctx, app.ScanOptions{
			Root: root, Output: *output, Format: *format, MaxFileSize: *maxFileSize, Boundaries: boundaries,
		})

	case "diff":
		fs := flag.NewFlagSet("diff", flag.ContinueOnError)
		format := fs.String("format", "terminal", "output format: terminal, json, or sarif")
		output := fs.String("output", "-", "output file, or - for stdout")
		failOn := fs.String("fail-on", "", "exit 2 at or above severity: info, low, medium, high, critical")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: opscustodian diff [--format terminal|json|sarif] <before> <after>")
		}
		return app.Diff(app.DiffOptions{Before: fs.Arg(0), After: fs.Arg(1), Format: *format, FailOn: *failOn, Output: *output})

	case "explain":
		fs := flag.NewFlagSet("explain", flag.ContinueOnError)
		reportPath := fs.String("report", "", "JSON drift report produced by opscustodian diff")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *reportPath == "" || fs.NArg() != 1 {
			return fmt.Errorf("usage: opscustodian explain --report <report.json> <finding-id>")
		}
		return app.Explain(app.ExplainOptions{Report: *reportPath, FindingID: fs.Arg(0)})

	case "findings":
		fs := flag.NewFlagSet("findings", flag.ContinueOnError)
		bom := fs.String("bom", "", "Agent BOM containing current-state findings")
		format := fs.String("format", "terminal", "output format: terminal, json, or sarif")
		output := fs.String("output", "-", "output file, or - for stdout")
		failOn := fs.String("fail-on", "", "exit 2 at or above severity: info, low, medium, high, critical")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bom == "" {
			return fmt.Errorf("usage: opscustodian findings --bom <agentbom> [flags]")
		}
		return app.Findings(app.FindingsOptions{BOM: *bom, Format: *format, FailOn: *failOn, Output: *output})

	case "check":
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		bom := fs.String("bom", "", "Agent BOM to evaluate")
		baseline := fs.String("baseline", "", "optional baseline Agent BOM for drift-aware policy")
		policyPath := fs.String("policy", "policies/builtin", "Rego file or policy directory")
		opa := fs.String("opa", "opa", "path to the OPA executable")
		query := fs.String("query", "data.opscustodian.decision", "OPA decision query")
		format := fs.String("format", "terminal", "output format: terminal or json")
		timeout := fs.Duration("timeout", 10*time.Second, "maximum OPA evaluation time")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bom == "" {
			return fmt.Errorf("usage: opscustodian check --bom <agentbom> [flags]")
		}
		return app.Check(ctx, app.CheckOptions{
			BOM: *bom, Baseline: *baseline, Policy: *policyPath, OPA: *opa,
			Query: *query, Format: *format, Timeout: *timeout,
		})

	case "report":
		fs := flag.NewFlagSet("report", flag.ContinueOnError)
		bom := fs.String("bom", "", "Agent BOM to render")
		output := fs.String("output", "opscustodian-report.html", "HTML output file, or - for stdout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bom == "" {
			return fmt.Errorf("usage: opscustodian report --bom <agentbom> [--output report.html]")
		}
		return app.InventoryReport(app.InventoryReportOptions{BOM: *bom, Output: *output})

	case "events":
		fs := flag.NewFlagSet("events", flag.ContinueOnError)
		bom := fs.String("bom", "", "Agent BOM to convert into audit events")
		driftReport := fs.String("drift", "", "JSON drift report to convert into audit events")
		output := fs.String("output", "-", "JSONL output file, or - for stdout")
		otlpEndpoint := fs.String("otlp-endpoint", "", "full OTLP/HTTP logs endpoint (opt-in)")
		otlpTimeout := fs.Duration("otlp-timeout", 10*time.Second, "OTLP request timeout (maximum 1m)")
		allowInsecureOTLP := fs.Bool("allow-insecure-otlp", false, "allow an explicit http OTLP endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		headerValue := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS")
		if headerValue == "" {
			headerValue = os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")
		}
		headers, err := audit.ParseOTLPHeaders(headerValue)
		if err != nil {
			return err
		}
		return app.Events(app.EventsOptions{
			BOM: *bom, Drift: *driftReport, Output: *output, OTLPEndpoint: *otlpEndpoint,
			OTLPHeaders: headers, OTLPTimeout: *otlpTimeout, AllowInsecureOTLP: *allowInsecureOTLP,
		})

	case "version", "--version", "-version":
		fs := flag.NewFlagSet("version", flag.ContinueOnError)
		format := fs.String("format", "terminal", "output format: terminal or json")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return writeVersion(os.Stdout, version, *format)

	case "help", "--help", "-h":
		printUsage()
		return nil

	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func writeVersion(w io.Writer, buildVersion, format string) error {
	info := contracts.BuildInfo(buildVersion)
	switch format {
	case "terminal":
		fmt.Fprintf(w, "opscustodian %s\n", info.Version)
		fmt.Fprintf(w, "Agent BOM: %s\n", info.Contracts.AgentBOM)
		fmt.Fprintf(w, "Normalization: %s\n", info.Contracts.Normalization)
		return nil
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	default:
		return fmt.Errorf("unsupported version format %q; expected terminal or json", format)
	}
}

func printUsage() {
	fmt.Print(`OpsCustodian discovers and governs agentic operational access.

Usage:
  opscustodian scan [flags] [path]
  opscustodian diff [flags] <before> <after>
  opscustodian explain --report <report.json> <finding-id>
  opscustodian findings --bom <agentbom> [--format terminal|json|sarif] [--fail-on high]
  opscustodian check --bom <agentbom> [flags]
  opscustodian report --bom <agentbom> [--output report.html]
  opscustodian events (--bom <agentbom> | --drift <drift.json>) [--output events.jsonl] [--otlp-endpoint URL]
  opscustodian version [--format terminal|json]

Commands:
  scan     discover agentic assets and emit an Agent BOM
  diff     compare two Agent BOM documents semantically
  explain  explain one finding from a JSON drift report
  findings render and enforce current-state Agent BOM findings
  check    evaluate Agent BOM and optional drift with OPA/Rego
  report   render a local read-only HTML inventory report
  events   convert scan or drift results into OpenTelemetry-compatible JSONL events
  version  print build and supported contract versions
`)
}
