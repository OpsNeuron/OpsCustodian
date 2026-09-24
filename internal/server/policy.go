package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/policy"
	"github.com/opscustodian/opscustodian/internal/validation"
)

type PolicyEvaluator interface {
	Evaluate(context.Context, policy.Input) (policy.Decision, error)
}

type PolicyEvaluatorFunc func(context.Context, policy.Input) (policy.Decision, error)

func (evaluate PolicyEvaluatorFunc) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	return evaluate(ctx, input)
}

type policyEvaluationResponse struct {
	Allowed  bool            `json:"allowed"`
	Decision policy.Decision `json:"decision"`
}

func (api *API) evaluatePolicy(w http.ResponseWriter, request *http.Request) {
	setPolicyEvaluationAudit(request, audit.PolicyEvaluationObservation{Result: "rejected"})
	if api.policy == nil {
		setPolicyEvaluationAudit(request, audit.PolicyEvaluationObservation{Result: "unavailable"})
		writeError(w, http.StatusServiceUnavailable, "policy-evaluator-unavailable", "policy evaluation is unavailable")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content-type-required", "Content-Type must be application/json")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, maximumSnapshotRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input policy.Input
	if err := decoder.Decode(&input); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "policy-input-too-large", fmt.Sprintf("policy input must not exceed %d bytes", maximumSnapshotRequestBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid-json", "request body must contain one valid policy input JSON document")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid-json", "request body must contain one valid policy input JSON document")
		return
	}
	if input.APIVersion != policy.InputAPIVersion || len(validation.Validate(input.BOM)) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid-policy-input", "policy input does not satisfy the supported contract")
		return
	}
	decision, err := api.policy.Evaluate(request.Context(), input)
	if err != nil {
		setPolicyEvaluationAudit(request, audit.PolicyEvaluationObservation{Result: "failed"})
		writeError(w, http.StatusServiceUnavailable, "policy-evaluation-failed", "policy evaluation failed")
		return
	}
	decision.Normalize()
	if err := decision.Validate(); err != nil {
		setPolicyEvaluationAudit(request, audit.PolicyEvaluationObservation{Result: "invalid"})
		writeError(w, http.StatusServiceUnavailable, "invalid-policy-decision", "policy evaluator returned an invalid decision")
		return
	}
	result := "allowed"
	if len(decision.Deny) > 0 {
		result = "denied"
	}
	setPolicyEvaluationAudit(request, audit.PolicyEvaluationObservation{Result: result, DenyCount: len(decision.Deny), WarnCount: len(decision.Warn)})
	writeJSON(w, http.StatusOK, valueResponse[policyEvaluationResponse]{
		APIVersion: contracts.ControlPlaneAPIVersion,
		Value:      policyEvaluationResponse{Allowed: len(decision.Deny) == 0, Decision: decision},
	})
}
