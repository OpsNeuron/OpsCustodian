package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

func WriteBOM(w io.Writer, bom model.AgentBOM, format string) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(bom)
	case "yaml", "yml":
		encoder := yaml.NewEncoder(w)
		encoder.SetIndent(2)
		defer encoder.Close()
		return encoder.Encode(bom)
	default:
		return fmt.Errorf("unsupported Agent BOM format %q", format)
	}
}

func WriteDiff(w io.Writer, value drift.Report, format string) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	case "terminal":
		fmt.Fprintf(w, "OpsCustodian semantic drift: %s -> %s\n", value.BeforeRevision, value.AfterRevision)
		if len(value.Changes) == 0 {
			fmt.Fprintln(w, "No semantic access changes detected.")
			return nil
		}
		for _, change := range value.Changes {
			fmt.Fprintf(w, "\n%-8s %s [%s]\n", strings.ToUpper(change.Severity), change.Subject, change.ID)
			fmt.Fprintf(w, "  Agent:  %s\n", change.AgentID)
			fmt.Fprintf(w, "  Change: %s\n", change.Type)
			if change.Before != "" { fmt.Fprintf(w, "  Before: %s\n", change.Before) }
			if change.After != "" { fmt.Fprintf(w, "  After:  %s\n", change.After) }
			fmt.Fprintf(w, "  Reason: %s\n", change.Reason)
		}
		return nil
	default:
		return fmt.Errorf("unsupported diff format %q", format)
	}
}

func WriteExplanation(w io.Writer, change drift.Change) error {
	fmt.Fprintf(w, "%s: %s\n", strings.ToUpper(change.Severity), change.Subject)
	fmt.Fprintf(w, "Finding: %s\n", change.ID)
	fmt.Fprintf(w, "Agent:   %s\n", change.AgentID)
	fmt.Fprintf(w, "Change:  %s\n", change.Type)
	if change.Before != "" { fmt.Fprintf(w, "Before:  %s\n", change.Before) }
	if change.After != "" { fmt.Fprintf(w, "After:   %s\n", change.After) }
	fmt.Fprintf(w, "Reason:  %s\n", change.Reason)
	return nil
}
