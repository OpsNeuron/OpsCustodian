package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/opscustodian/opscustodian/internal/app"
)

var version = "dev"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var exitErr *app.ExitError
		if errors.As(err, &exitErr) { os.Exit(exitErr.Code) }
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
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		root := "."
		if fs.NArg() > 0 {
			root = fs.Arg(0)
		}
		return app.Scan(ctx, app.ScanOptions{
			Root: root, Output: *output, Format: *format, MaxFileSize: *maxFileSize,
		})

	case "diff":
		fs := flag.NewFlagSet("diff", flag.ContinueOnError)
		format := fs.String("format", "terminal", "output format: terminal or json")
		failOn := fs.String("fail-on", "", "exit 2 at or above severity: info, low, medium, high, critical")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: opscustodian diff [--format terminal|json] <before> <after>")
		}
		return app.Diff(app.DiffOptions{Before: fs.Arg(0), After: fs.Arg(1), Format: *format, FailOn: *failOn})

	case "explain":
		fs := flag.NewFlagSet("explain", flag.ContinueOnError)
		reportPath := fs.String("report", "", "JSON drift report produced by opscustodian diff")
		if err := fs.Parse(args[1:]); err != nil { return err }
		if *reportPath == "" || fs.NArg() != 1 {
			return fmt.Errorf("usage: opscustodian explain --report <report.json> <finding-id>")
		}
		return app.Explain(app.ExplainOptions{Report: *reportPath, FindingID: fs.Arg(0)})

	case "version", "--version", "-version":
		fmt.Printf("opscustodian %s\n", version)
		return nil

	case "help", "--help", "-h":
		printUsage()
		return nil

	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Print(`OpsCustodian discovers and governs agentic operational access.

Usage:
  opscustodian scan [flags] [path]
  opscustodian diff [flags] <before> <after>
  opscustodian explain --report <report.json> <finding-id>
  opscustodian version

Commands:
  scan     discover agentic assets and emit an Agent BOM
  diff     compare two Agent BOM documents semantically
  explain  explain one finding from a JSON drift report
  version  print build version
`)
}
