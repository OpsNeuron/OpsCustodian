package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/store"
)

type RequestAuditSink interface {
	Record(context.Context, audit.Event)
}

type requestAuditOptions struct {
	Now       func() time.Time
	RequestID func() (string, error)
}

type requestAuditState struct{ authentication string }
type requestAuditContextKey struct{}

func NewAuditedAuthenticatedHandler(reader store.Reader, buildVersion string, authenticator BearerAuthenticator, organizationID string, sink RequestAuditSink) (http.Handler, error) {
	return newAuditedAuthenticatedHandler(reader, buildVersion, authenticator, organizationID, sink, requestAuditOptions{Now: time.Now, RequestID: randomRequestID})
}

func newAuditedAuthenticatedHandler(reader store.Reader, buildVersion string, authenticator BearerAuthenticator, organizationID string, sink RequestAuditSink, options requestAuditOptions) (http.Handler, error) {
	if sink == nil {
		return nil, fmt.Errorf("request audit sink is required")
	}
	if !store.ValidOrganizationID(organizationID) {
		return nil, fmt.Errorf("valid audit organization ID is required")
	}
	if options.Now == nil || options.RequestID == nil {
		return nil, fmt.Errorf("complete request audit dependencies are required")
	}
	return requestAuditMiddleware(newHandler(reader, buildVersion, &authenticator), organizationID, sink, options), nil
}

func requestAuditMiddleware(next http.Handler, organizationID string, sink RequestAuditSink, options requestAuditOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := options.Now().UTC()
		requestID, err := options.RequestID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "request-id-unavailable", "request could not be initialized")
			return
		}
		w.Header().Set("X-Request-ID", requestID)
		state := &requestAuditState{authentication: "unknown"}
		auditedRequest := request.WithContext(context.WithValue(request.Context(), requestAuditContextKey{}, state))
		response := &auditResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(response, auditedRequest)
		finished := options.Now().UTC()
		route := auditedRequest.Pattern
		if route == "" {
			route = "unmatched"
		}
		sink.Record(auditedRequest.Context(), audit.FromHTTPRequest(audit.HTTPRequestObservation{
			OccurredAt: started, RequestID: requestID,
			OrganizationID: organizationID, Method: request.Method, Route: route,
			Status: response.status, DurationMillis: max(finished.Sub(started).Milliseconds(), 0),
			Authentication: state.authentication,
		}))
	})
}

type auditResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (writer *auditResponseWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.wroteHeader = true
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func setRequestAuthentication(request *http.Request, value string) {
	if state, ok := request.Context().Value(requestAuditContextKey{}).(*requestAuditState); ok {
		state.authentication = value
	}
}

func randomRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(value[:]), nil
}
