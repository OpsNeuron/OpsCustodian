package controlplane

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewHTTPServerUsesBoundedLoopbackConfiguration(t *testing.T) {
	config := defaultHTTPConfig()
	server, err := NewHTTPServer(config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	if server.Addr != "127.0.0.1:8080" || server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second || server.WriteTimeout != 30*time.Second || server.IdleTimeout != time.Minute || server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("HTTP server = %#v", server)
	}
}

func TestHTTPConfigRejectsExposureAndUnboundedInputs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*HTTPConfig)
		message string
	}{
		{"all interfaces", func(value *HTTPConfig) { value.ListenAddress = "0.0.0.0:8080" }, "loopback"},
		{"hostname", func(value *HTTPConfig) { value.ListenAddress = "localhost:8080" }, "loopback"},
		{"missing port", func(value *HTTPConfig) { value.ListenAddress = "127.0.0.1" }, "host and port"},
		{"invalid port", func(value *HTTPConfig) { value.ListenAddress = "127.0.0.1:0" }, "between"},
		{"header timeout", func(value *HTTPConfig) { value.ReadHeaderTimeout = 0 }, "READ_HEADER"},
		{"short read timeout", func(value *HTTPConfig) { value.ReadTimeout = time.Second }, "shorter"},
		{"large headers", func(value *HTTPConfig) { value.MaxHeaderBytes = 2 << 20 }, "MAX_HEADER"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := defaultHTTPConfig()
			test.mutate(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
	config := defaultHTTPConfig()
	config.ListenAddress = "[::1]:9090"
	if err := config.Validate(); err != nil {
		t.Fatalf("IPv6 loopback rejected: %v", err)
	}
}

func TestServeHTTPShutsDownAfterCancellation(t *testing.T) {
	server := newFakeManagedHTTPServer()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHTTP(ctx, fakeListener{}, server, time.Second) }()
	<-server.started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if server.shutdowns != 1 {
		t.Fatalf("Shutdown() calls = %d", server.shutdowns)
	}
}

func TestServeHTTPPropagatesServeAndShutdownFailures(t *testing.T) {
	serveFailure := newFakeManagedHTTPServer()
	serveFailure.serveError = errors.New("listener failure")
	if err := serveHTTP(context.Background(), fakeListener{}, serveFailure, time.Second); err == nil || !strings.Contains(err.Error(), "listener failure") {
		t.Fatalf("serve error = %v", err)
	}

	shutdownFailure := newFakeManagedHTTPServer()
	shutdownFailure.shutdownError = errors.New("shutdown failure")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHTTP(ctx, fakeListener{}, shutdownFailure, time.Second) }()
	<-shutdownFailure.started
	cancel()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "shutdown failure") {
		t.Fatalf("shutdown error = %v", err)
	}
}

type fakeManagedHTTPServer struct {
	started       chan struct{}
	stopped       chan struct{}
	serveError    error
	shutdownError error
	shutdowns     int
	once          sync.Once
}

func newFakeManagedHTTPServer() *fakeManagedHTTPServer {
	return &fakeManagedHTTPServer{started: make(chan struct{}), stopped: make(chan struct{})}
}

func (server *fakeManagedHTTPServer) Serve(net.Listener) error {
	close(server.started)
	if server.serveError != nil {
		return server.serveError
	}
	<-server.stopped
	return http.ErrServerClosed
}

func (server *fakeManagedHTTPServer) Shutdown(context.Context) error {
	server.shutdowns++
	if server.shutdownError != nil {
		return server.shutdownError
	}
	server.once.Do(func() { close(server.stopped) })
	return nil
}

type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (fakeListener) Close() error              { return nil }
func (fakeListener) Addr() net.Addr            { return fakeAddress("127.0.0.1:8080") }

type fakeAddress string

func (fakeAddress) Network() string      { return "tcp" }
func (value fakeAddress) String() string { return string(value) }
