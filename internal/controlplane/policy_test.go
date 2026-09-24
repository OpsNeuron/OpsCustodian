package controlplane

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNewPolicyEvaluatorUsesBoundedRuntimeConfiguration(t *testing.T) {
	if evaluator := newPolicyEvaluator(Config{}); evaluator != nil {
		t.Fatal("policy evaluator was enabled without a policy path")
	}
	config := Config{
		PolicyPath:    filepath.Join(t.TempDir(), "policies"),
		PolicyBinary:  "opa-custom",
		PolicyQuery:   "data.example.decision",
		PolicyTimeout: 7 * time.Second,
	}
	evaluator := newPolicyEvaluator(config)
	if evaluator == nil || evaluator.options.PolicyPath != config.PolicyPath || evaluator.options.BinaryPath != "opa-custom" || evaluator.options.Query != "data.example.decision" || evaluator.timeout != 7*time.Second {
		t.Fatalf("unexpected evaluator configuration: %#v", evaluator)
	}
}
