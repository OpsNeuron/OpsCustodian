package controlplane

import (
	"context"
	"time"

	"github.com/opscustodian/opscustodian/internal/policy"
)

type opaPolicyEvaluator struct {
	options policy.OPAOptions
	timeout time.Duration
}

func newPolicyEvaluator(config Config) *opaPolicyEvaluator {
	if config.PolicyPath == "" {
		return nil
	}
	return &opaPolicyEvaluator{
		options: policy.OPAOptions{
			BinaryPath: config.PolicyBinary,
			PolicyPath: config.PolicyPath,
			Query:      config.PolicyQuery,
		},
		timeout: config.PolicyTimeout,
	}
}

func (evaluator *opaPolicyEvaluator) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	evaluationContext, cancel := context.WithTimeout(ctx, evaluator.timeout)
	defer cancel()
	return policy.EvaluateOPA(evaluationContext, input, evaluator.options)
}
