package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opscustodian/opscustodian/internal/app"
	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/controlplane"
	"github.com/opscustodian/opscustodian/internal/preflight"
)

var version = "dev"

type stringListFlag []string

func (values *stringListFlag) String() string         { return fmt.Sprint([]string(*values)) }
func (values *stringListFlag) Set(value string) error { *values = append(*values, value); return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
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
		source := fs.String("source", "", "portable repository source identifier (for example github:owner/repository)")
		revision := fs.String("revision", "working-tree", "repository revision identifier")
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
			Root: root, Source: *source, Revision: *revision, Output: *output, Format: *format, MaxFileSize: *maxFileSize, Boundaries: boundaries,
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

	case "serve":
		return serveCommand(ctx, args[1:], os.LookupEnv, os.Stdout, controlplane.DefaultProcessDependencies, controlplane.RunProcess, version)

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		profile := fs.String("profile", "release", "preflight profile: server, policy, release, or beta")
		format := fs.String("format", "terminal", "output format: terminal or json")
		root := fs.String("root", ".", "repository root for release checks")
		opa := fs.String("opa", "opa", "path or name of the OPA executable")
		policyPath := fs.String("policy", "policies/builtin", "Rego file or policy directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("usage: opscustodian doctor [--profile server|policy|release|beta] [flags]")
		}
		report := preflight.Evaluate(preflight.Options{Profile: *profile, Root: *root, OPAPath: *opa, PolicyPath: *policyPath, LookupEnv: os.LookupEnv})
		if err := preflight.Write(os.Stdout, report, *format); err != nil {
			return err
		}
		if !report.Ready {
			return &app.ExitError{Code: 2, Err: errors.New("preflight checks failed")}
		}
		return nil

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

type processDependencyFactory func() (controlplane.ProcessDependencies, error)
type processRunner func(context.Context, controlplane.Config, string, controlplane.ProcessDependencies) error

func serveCommand(ctx context.Context, args []string, lookup controlplane.LookupEnv, output io.Writer, dependencyFactory processDependencyFactory, runner processRunner, buildVersion string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	printConfig := fs.Bool("print-config", false, "validate and print secret-free effective configuration without starting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: opscustodian serve [--print-config]")
	}
	config, err := controlplane.ConfigFromEnvironment(lookup)
	if err != nil {
		return err
	}
	if *printConfig {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.Safe())
	}
	if dependencyFactory == nil || runner == nil {
		return fmt.Errorf("control-plane process dependencies are required")
	}
	dependencies, err := dependencyFactory()
	if err != nil {
		return fmt.Errorf("initialize control-plane dependencies: %w", err)
	}
	return runner(ctx, config, buildVersion, dependencies)
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
  opscustodian serve [--print-config]
  opscustodian doctor [--profile server|policy|release|beta] [--format terminal|json]
  opscustodian version [--format terminal|json]

Commands:
  scan     discover agentic assets and emit an Agent BOM
  diff     compare two Agent BOM documents semantically
  explain  explain one finding from a JSON drift report
  findings render and enforce current-state Agent BOM findings
  check    evaluate Agent BOM and optional drift with OPA/Rego
  report   render a local read-only HTML inventory report
  events   convert scan or drift results into OpenTelemetry-compatible JSONL events
  serve    run the authenticated loopback organization control plane
  doctor   validate offline integration and release prerequisites without network I/O
  version  print build and supported contract versions
`)
}
