package controlplane

import (
	"fmt"
	"net/http"

	"github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func NewControlPlaneHTTPServer(config Config, reader store.Reader, buildVersion string, auditSink server.RequestAuditSink, onAuditFailure server.RequestAuditFailureHandler) (*http.Server, error) {
	return NewControlPlaneHTTPServerWithReadiness(config, reader, buildVersion, auditSink, onAuditFailure, nil)
}

func NewControlPlaneHTTPServerWithReadiness(config Config, reader store.Reader, buildVersion string, auditSink server.RequestAuditSink, onAuditFailure server.RequestAuditFailureHandler, readiness server.ReadinessReader) (*http.Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("control-plane store reader is required")
	}
	handler, err := server.NewAuditedAuthenticatedHandlerWithReadiness(reader, buildVersion, config.Authenticator, config.Authorizer, config.OrganizationID, auditSink, onAuditFailure, readiness)
	if err != nil {
		return nil, err
	}
	return NewHTTPServer(config.HTTP, handler)
}
