package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type OPAOptions struct {
	BinaryPath string
	PolicyPath string
	Query      string
	MaxOutput  int
}

type opaResponse struct {
	Result []struct {
		Expressions []struct {
			Value json.RawMessage `json:"value"`
		} `json:"expressions"`
	} `json:"result"`
}

func EvaluateOPA(ctx context.Context, input Input, opts OPAOptions) (Decision, error) {
	if opts.BinaryPath == "" {
		opts.BinaryPath = "opa"
	}
	if opts.Query == "" {
		opts.Query = "data.opscustodian.decision"
	}
	if opts.MaxOutput <= 0 {
		opts.MaxOutput = 4 << 20
	}
	policyPath, err := filepath.Abs(opts.PolicyPath)
	if err != nil {
		return Decision{}, fmt.Errorf("resolve policy path: %w", err)
	}
	if info, err := os.Stat(policyPath); err != nil {
		return Decision{}, fmt.Errorf("inspect policy path: %w", err)
	} else if !info.IsDir() && filepath.Ext(policyPath) != ".rego" {
		return Decision{}, fmt.Errorf("policy path must be a directory or .rego file")
	}

	inputFile, err := os.CreateTemp("", "opscustodian-policy-input-*.json")
	if err != nil {
		return Decision{}, fmt.Errorf("create temporary policy input: %w", err)
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)
	if err := inputFile.Chmod(0o600); err != nil {
		inputFile.Close()
		return Decision{}, fmt.Errorf("protect temporary policy input: %w", err)
	}
	if err := json.NewEncoder(inputFile).Encode(input); err != nil {
		inputFile.Close()
		return Decision{}, fmt.Errorf("encode policy input: %w", err)
	}
	if err := inputFile.Close(); err != nil {
		return Decision{}, fmt.Errorf("close temporary policy input: %w", err)
	}

	stdout := newLimitedBuffer(opts.MaxOutput)
	stderr := newLimitedBuffer(opts.MaxOutput)
	command := exec.CommandContext(ctx, opts.BinaryPath,
		"eval", "--format=json", "--data", policyPath, "--input", inputPath, opts.Query,
	)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return Decision{}, fmt.Errorf("OPA evaluation timed out or was cancelled: %w", ctx.Err())
		}
		return Decision{}, fmt.Errorf("OPA evaluation failed: %w: %s", err, stderr.String())
	}
	if stdout.Truncated() {
		return Decision{}, fmt.Errorf("OPA output exceeded %d bytes", opts.MaxOutput)
	}

	var response opaResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return Decision{}, fmt.Errorf("decode OPA response: %w", err)
	}
	if len(response.Result) == 0 || len(response.Result[0].Expressions) == 0 {
		return Decision{}, fmt.Errorf("OPA query %q returned no decision", opts.Query)
	}
	var decision Decision
	if err := json.Unmarshal(response.Result[0].Expressions[0].Value, &decision); err != nil {
		return Decision{}, fmt.Errorf("decode policy decision: %w", err)
	}
	decision.Normalize()
	if err := decision.Validate(); err != nil {
		return Decision{}, fmt.Errorf("invalid policy decision: %w", err)
	}
	return decision, nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{remaining: limit}
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if len(value) > buffer.remaining {
		value = value[:buffer.remaining]
		buffer.truncated = true
	}
	if len(value) > 0 {
		_, _ = buffer.buffer.Write(value)
		buffer.remaining -= len(value)
	}
	return originalLength, nil
}

func (buffer *limitedBuffer) Bytes() []byte { return buffer.buffer.Bytes() }
func (buffer *limitedBuffer) String() string { return buffer.buffer.String() }
func (buffer *limitedBuffer) Truncated() bool { return buffer.truncated }
