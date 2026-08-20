package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestRequestAuditCapturesCanonicalSecretSafeAPIEvent(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	authorizer, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	sink := &recordingRequestAuditSink{}
	times := []time.Time{
		time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 20, 10, 0, 0, int(12*time.Millisecond), time.UTC),
	}
	handler, err := newAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "organization-0123456789abcdef", sink, func(err error) { t.Fatalf("audit failure: %v", err) }, requestAuditOptions{
		Now:       func() time.Time { value := times[0]; times = times[1:]; return value },
		RequestID: func() (string, error) { return "request-0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	secret := "secret-query-value"
	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories?cursor="+secret, nil)
	request.Header.Set("Authorization", "Bearer "+serverTestBearerToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("X-Request-ID") == "" || len(sink.events) != 1 {
		t.Fatalf("response = %d, events = %#v", response.Code, sink.events)
	}
	event := sink.events[0]
	if event.EventName != "opscustodian.http.request.completed" || event.Attributes["http.route"] != "GET /api/v1/repositories" || event.Attributes["opscustodian.authentication.result"] != "authenticated" || event.Attributes["opscustodian.authorization.result"] != "authorized" || event.Attributes["http.response.status_code"] != http.StatusBadRequest || event.Attributes["http.server.request.duration_ms"] != int64(12) {
		t.Fatalf("audit event = %#v", event)
	}
	content, _ := json.Marshal(event)
	if strings.Contains(string(content), secret) || strings.Contains(string(content), serverTestBearerToken) || strings.Contains(string(content), "Authorization") {
		t.Fatalf("audit event leaked request secret: %s", content)
	}
}

func TestRequestAuditDistinguishesRejectedAndPublicRequests(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	authorizer, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	sink := &recordingRequestAuditSink{}
	handler, err := newAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "organization-0123456789abcdef", sink, func(err error) { t.Fatalf("audit failure: %v", err) }, requestAuditOptions{
		Now: time.Now, RequestID: func() (string, error) { return "request-0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if len(sink.events) != 2 || sink.events[0].Attributes["opscustodian.authentication.result"] != "rejected" || sink.events[0].Attributes["http.response.status_code"] != http.StatusUnauthorized || sink.events[1].Attributes["opscustodian.authentication.result"] != "public" || sink.events[1].Attributes["http.route"] != "GET /healthz" {
		t.Fatalf("audit events = %#v", sink.events)
	}
}

func TestRequestAuditRequiresSafeDependencies(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	authorizer, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	if _, err := NewAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "bad", &recordingRequestAuditSink{}, func(error) {}); err == nil {
		t.Fatal("invalid organization was accepted")
	}
	if _, err := NewAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "organization-0123456789abcdef", nil, func(error) {}); err == nil {
		t.Fatal("missing audit sink was accepted")
	}
	if _, err := NewAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "organization-0123456789abcdef", &recordingRequestAuditSink{}, nil); err == nil {
		t.Fatal("missing audit failure handler was accepted")
	}
}

func TestRequestAuditReportsSinkFailureAfterResponse(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	authorizer, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	var reported error
	handler, err := newAuditedAuthenticatedHandler(store.NewMemory(), "test", authenticator, authorizer, "organization-0123456789abcdef", failingRequestAuditSink{}, func(err error) { reported = err }, requestAuditOptions{
		Now: time.Now, RequestID: func() (string, error) { return "request-0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if reported == nil || !strings.Contains(reported.Error(), "sink failure") {
		t.Fatalf("reported audit failure = %v", reported)
	}
}

type recordingRequestAuditSink struct{ events []audit.Event }

func (sink *recordingRequestAuditSink) Record(_ context.Context, event audit.Event) error {
	sink.events = append(sink.events, event)
	return nil
}

type failingRequestAuditSink struct{}

func (failingRequestAuditSink) Record(context.Context, audit.Event) error {
	return errors.New("sink failure")
}
