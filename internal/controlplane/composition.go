package controlplane

import (
	"fmt"
	"net/http"

	"github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func NewControlPlaneHTTPServer(config Config, reader store.Reader, buildVersion string, auditSink server.RequestAuditSink, onAuditFailure server.RequestAuditFailureHandler) (*http.Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("control-plane store reader is required")
	}
	handler, err := server.NewAuditedAuthenticatedHandler(reader, buildVersion, config.Authenticator, config.Authorizer, config.OrganizationID, auditSink, onAuditFailure)
	if err != nil {
		return nil, err
	}
	return NewHTTPServer(config.HTTP, handler)
}
