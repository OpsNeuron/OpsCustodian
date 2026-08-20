package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (config HTTPConfig) Validate() error {
	host, portText, err := net.SplitHostPort(config.ListenAddress)
	if err != nil {
		return fmt.Errorf("OPSCUSTODIAN_HTTP_LISTEN_ADDRESS must be an IP host and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("OPSCUSTODIAN_HTTP_LISTEN_ADDRESS must use a loopback IP until authentication is enabled")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("OPSCUSTODIAN_HTTP_LISTEN_ADDRESS port must be between 1 and 65535")
	}
	if err := boundedHTTPDuration("OPSCUSTODIAN_HTTP_READ_HEADER_TIMEOUT", config.ReadHeaderTimeout); err != nil {
		return err
	}
	if err := boundedHTTPDuration("OPSCUSTODIAN_HTTP_READ_TIMEOUT", config.ReadTimeout); err != nil {
		return err
	}
	if config.ReadTimeout < config.ReadHeaderTimeout {
		return fmt.Errorf("OPSCUSTODIAN_HTTP_READ_TIMEOUT must not be shorter than header timeout")
	}
	if err := boundedHTTPDuration("OPSCUSTODIAN_HTTP_WRITE_TIMEOUT", config.WriteTimeout); err != nil {
		return err
	}
	if err := boundedHTTPDuration("OPSCUSTODIAN_HTTP_IDLE_TIMEOUT", config.IdleTimeout); err != nil {
		return err
	}
	if config.MaxHeaderBytes < 8<<10 || config.MaxHeaderBytes > 1<<20 {
		return fmt.Errorf("OPSCUSTODIAN_HTTP_MAX_HEADER_BYTES must be between 8192 and 1048576")
	}
	return nil
}

func NewHTTPServer(config HTTPConfig, handler http.Handler) (*http.Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if handler == nil {
		return nil, fmt.Errorf("HTTP handler is required")
	}
	return &http.Server{
		Addr: config.ListenAddress, Handler: handler,
		ReadHeaderTimeout: config.ReadHeaderTimeout, ReadTimeout: config.ReadTimeout,
		WriteTimeout: config.WriteTimeout, IdleTimeout: config.IdleTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}, nil
}

type managedHTTPServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

func serveHTTP(ctx context.Context, listener net.Listener, server managedHTTPServer, shutdownTimeout time.Duration) error {
	if listener == nil || server == nil {
		return fmt.Errorf("HTTP listener and server are required")
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve control-plane HTTP: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown control-plane HTTP: %w", err)
		}
		select {
		case err := <-serveErrors:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve control-plane HTTP: %w", err)
			}
			return nil
		case <-shutdownContext.Done():
			return fmt.Errorf("wait for control-plane HTTP shutdown: %w", shutdownContext.Err())
		}
	}
}

func boundedHTTPDuration(name string, value time.Duration) error {
	if value <= 0 || value > 5*time.Minute {
		return fmt.Errorf("%s must be between 1ns and 5m", name)
	}
	return nil
}
