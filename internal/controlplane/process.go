package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/server"
)

type ProcessDependencies struct {
	Database         Dependencies
	Listen           func(string, string) (net.Listener, error)
	Serve            func(context.Context, net.Listener, managedHTTPServer, Config) error
	AuditSink        server.RequestAuditSink
	WatchCredentials func(context.Context, *server.CredentialRegistry, string, time.Duration, server.CredentialReloadObserver) error
}

func DefaultProcessDependencies() (ProcessDependencies, error) {
	database, err := PostgresDependencies()
	if err != nil {
		return ProcessDependencies{}, err
	}
	auditSink, err := audit.NewJSONLineSink(os.Stderr)
	if err != nil {
		return ProcessDependencies{}, err
	}
	return ProcessDependencies{
		Database:  database,
		AuditSink: auditSink,
		Listen:    net.Listen,
		Serve: func(ctx context.Context, listener net.Listener, server managedHTTPServer, config Config) error {
			return serveHTTP(ctx, listener, server, config.ShutdownTimeout)
		},
		WatchCredentials: server.WatchCredentialFile,
	}, nil
}

func RunProcess(ctx context.Context, config Config, buildVersion string, dependencies ProcessDependencies) (resultErr error) {
	if dependencies.Listen == nil || dependencies.Serve == nil || dependencies.AuditSink == nil || dependencies.WatchCredentials == nil {
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

	auditFailures := make(chan error, 1)
	httpServer, err := NewControlPlaneHTTPServer(config, runtime.Store, buildVersion, dependencies.AuditSink, func(err error) {
		select {
		case auditFailures <- err:
		default:
		}
	})
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
	serveContext, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	serveResult := make(chan error, 1)
	go func() { serveResult <- dependencies.Serve(serveContext, listener, httpServer, config) }()
	var watcherResult <-chan error
	if config.CredentialFile != "" {
		results := make(chan error, 1)
		watcherResult = results
		go func() {
			results <- dependencies.WatchCredentials(serveContext, config.CredentialRegistry, config.CredentialFile, config.CredentialReloadInterval, func(result server.CredentialReloadResult) {
				err := dependencies.AuditSink.Record(serveContext, audit.FromCredentialReload(audit.CredentialReloadObservation{OccurredAt: result.OccurredAt, OrganizationID: config.OrganizationID, Succeeded: result.Succeeded}))
				if err != nil {
					select {
					case auditFailures <- fmt.Errorf("record credential reload audit: %w", err):
					default:
					}
				}
			})
		}()
	}
	select {
	case err := <-serveResult:
		return err
	case auditErr := <-auditFailures:
		cancelServe()
		serveErr := <-serveResult
		if serveErr != nil {
			return errors.Join(auditErr, serveErr)
		}
		return auditErr
	case watcherErr := <-watcherResult:
		cancelServe()
		serveErr := <-serveResult
		if watcherErr != nil || serveErr != nil {
			return errors.Join(watcherErr, serveErr)
		}
		return nil
	}
}

var _ managedHTTPServer = (*http.Server)(nil)
