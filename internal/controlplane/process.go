package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

type ProcessDependencies struct {
	Database Dependencies
	Listen   func(string, string) (net.Listener, error)
	Serve    func(context.Context, net.Listener, managedHTTPServer, Config) error
}

func DefaultProcessDependencies() (ProcessDependencies, error) {
	database, err := PostgresDependencies()
	if err != nil {
		return ProcessDependencies{}, err
	}
	return ProcessDependencies{
		Database: database,
		Listen:   net.Listen,
		Serve: func(ctx context.Context, listener net.Listener, server managedHTTPServer, config Config) error {
			return serveHTTP(ctx, listener, server, config.ShutdownTimeout)
		},
	}, nil
}

func RunProcess(ctx context.Context, config Config, buildVersion string, dependencies ProcessDependencies) (resultErr error) {
	if dependencies.Listen == nil || dependencies.Serve == nil {
		return fmt.Errorf("complete control-plane process dependencies are required")
	}
	runtime, err := Bootstrap(ctx, config, dependencies.Database)
	if err != nil {
		return err
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close PostgreSQL database: %w", err))
		}
	}()

	httpServer, err := NewControlPlaneHTTPServer(config, runtime.Store, buildVersion)
	if err != nil {
		return err
	}
	listener, err := dependencies.Listen("tcp", config.HTTP.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for control-plane HTTP: %w", err)
	}
	if listener == nil {
		return fmt.Errorf("listen for control-plane HTTP: dependency returned nil listener")
	}
	defer listener.Close()
	if err := dependencies.Serve(ctx, listener, httpServer, config); err != nil {
		return err
	}
	return nil
}

var _ managedHTTPServer = (*http.Server)(nil)
