package controlplane

import (
	"fmt"
	"net/http"

	"github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func NewControlPlaneHTTPServer(config Config, reader store.Reader, buildVersion string) (*http.Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("control-plane store reader is required")
	}
	handler := server.NewAuthenticatedHandler(reader, buildVersion, config.Authenticator)
	return NewHTTPServer(config.HTTP, handler)
}
