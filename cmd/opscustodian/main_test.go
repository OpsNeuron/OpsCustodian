package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/contracts"
)

func TestWriteVersionSupportsTerminalAndMachineReadableContracts(t *testing.T) {
	var terminal bytes.Buffer
	if err := writeVersion(&terminal, "v0.4.0-test", "terminal"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "opscustodian v0.4.0-test") || !strings.Contains(terminal.String(), contracts.AgentBOMAPIVersion) {
		t.Fatalf("terminal version output is incomplete: %s", terminal.String())
	}

	var output bytes.Buffer
	if err := writeVersion(&output, "v0.4.0-test", "json"); err != nil {
		t.Fatal(err)
	}
	var info contracts.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("invalid version JSON: %v", err)
	}
	if info.Version != "v0.4.0-test" || info.Contracts.PolicyInput != contracts.PolicyInputAPIVersion {
		t.Fatalf("unexpected version JSON: %#v", info)
	}
	if err := writeVersion(&bytes.Buffer{}, "dev", "yaml"); err == nil || !strings.Contains(err.Error(), "unsupported version format") {
		t.Fatalf("unsupported format error = %v", err)
	}
}
