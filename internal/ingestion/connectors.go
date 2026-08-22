package ingestion

import (
	"context"
	"fmt"
	"strings"
)

type Connector interface {
	Name() string
	Fetch(context.Context, Repository, string) (FetchResult, error)
}

type ConnectorRegistry struct {
	connectors map[string]Connector
}

func NewConnectorRegistry(connectors ...Connector) (*ConnectorRegistry, error) {
	registry := &ConnectorRegistry{connectors: make(map[string]Connector, len(connectors))}
	for index, connector := range connectors {
		if connector == nil {
			return nil, fmt.Errorf("connector at index %d is required", index)
		}
		name := strings.TrimSpace(connector.Name())
		if name == "" || name != connector.Name() {
			return nil, fmt.Errorf("connector at index %d has invalid name", index)
		}
		if _, exists := registry.connectors[name]; exists {
			return nil, fmt.Errorf("duplicate connector %q", name)
		}
		registry.connectors[name] = connector
	}
	if len(registry.connectors) == 0 {
		return nil, fmt.Errorf("at least one connector is required")
	}
	return registry, nil
}

func (registry *ConnectorRegistry) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	if registry == nil {
		return FetchResult{}, fmt.Errorf("connector registry is not initialized")
	}
	connector := registry.connectors[request.Repository.Connector]
	if connector == nil {
		return FetchResult{}, fmt.Errorf("unsupported repository connector %q", request.Repository.Connector)
	}
	return connector.Fetch(ctx, request.Repository, request.KnownRevision)
}
