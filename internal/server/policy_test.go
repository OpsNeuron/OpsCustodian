package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/policy"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestPolicyEvaluationReturnsExplicitAllowAndDeny(t *testing.T) {
	for _, test := range []struct {
		name     string
		decision policy.Decision
		allowed  string
	}{
		{name: "allow", decision: policy.Decision{Deny: []policy.Message{}, Warn: []policy.Message{}}, allowed: `"allowed":true`},
		{name: "deny", decision: policy.Decision{Deny: []policy.Message{{Rule: "deny-admin", Title: "Admin access", Message: "admin access is denied", Severity: "critical"}}, Warn: []policy.Message{}}, allowed: `"allowed":false`},
	} {
		t.Run(test.name, func(t *testing.T) {
			evaluator := PolicyEvaluatorFunc(func(_ context.Context, input policy.Input) (policy.Decision, error) {
				if input.APIVersion != policy.InputAPIVersion || input.BOM.Metadata.Source != "github:acme/platform" {
					t.Fatalf("unexpected policy input: %#v", input)
				}
				return test.decision, nil
			})
			handler := newHandlerWithReadinessAndPolicy(store.NewMemory(), "test", nil, nil, readyReadiness{}, evaluator)
			response := performPolicyRequest(t, handler, validPolicyInput(t))
			assertResponse(t, response, http.StatusOK, test.allowed, `"decision":`, `"deny":`, `"warn":`)
		})
	}
}

func TestPolicyEvaluationFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		evaluator PolicyEvaluator
		body      string
		status    int
		code      string
	}{
		{name: "unavailable", body: validPolicyInput(t), status: http.StatusServiceUnavailable, code: "policy-evaluator-unavailable"},
		{name: "evaluation failure", evaluator: PolicyEvaluatorFunc(func(context.Context, policy.Input) (policy.Decision, error) {
			return policy.Decision{}, errors.New("provider detail")
		}), body: validPolicyInput(t), status: http.StatusServiceUnavailable, code: "policy-evaluation-failed"},
		{name: "invalid decision", evaluator: PolicyEvaluatorFunc(func(context.Context, policy.Input) (policy.Decision, error) {
			return policy.Decision{Deny: nil, Warn: nil}, nil
		}), body: validPolicyInput(t), status: http.StatusServiceUnavailable, code: "invalid-policy-decision"},
		{name: "invalid input", evaluator: PolicyEvaluatorFunc(func(context.Context, policy.Input) (policy.Decision, error) {
			t.Fatal("evaluator called for invalid input")
			return policy.Decision{}, nil
		}), body: `{}`, status: http.StatusUnprocessableEntity, code: "invalid-policy-input"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandlerWithReadinessAndPolicy(store.NewMemory(), "test", nil, nil, readyReadiness{}, test.evaluator)
			response := performPolicyRequest(t, handler, test.body)
			assertResponse(t, response, test.status, `"code":"`+test.code+`"`)
			if strings.Contains(response.Body.String(), "provider detail") {
				t.Fatal("policy provider error leaked to the response")
			}
		})
	}
}

func TestPolicyEvaluationRequiresDedicatedScope(t *testing.T) {
	readToken := "policy-read-token-0123456789abcdefghijkl"
	policyToken := "policy-evaluate-token-0123456789abcdefgh"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{
		{ID: "reader", Token: readToken, Scopes: []string{ScopeControlPlaneRead}},
		{ID: "policy", Token: policyToken, Scopes: []string{ScopePolicyEvaluate}},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator := PolicyEvaluatorFunc(func(context.Context, policy.Input) (policy.Decision, error) {
		return policy.Decision{Deny: []policy.Message{}, Warn: []policy.Message{}}, nil
	})
	handler := newHandlerWithReadinessAndPolicy(store.NewMemory(), "test", &authenticator, &authorizer, readyReadiness{}, evaluator)
	body := validPolicyInput(t)
	for _, test := range []struct {
		token  string
		status int
	}{{readToken, http.StatusForbidden}, {policyToken, http.StatusOK}} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/evaluate", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
		}
	}
}

func validPolicyInput(t *testing.T) string {
	t.Helper()
	content, err := json.Marshal(policy.Input{APIVersion: policy.InputAPIVersion, BOM: serverTestBOM()})
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func performPolicyRequest(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/evaluate", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
