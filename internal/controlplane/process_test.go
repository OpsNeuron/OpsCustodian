package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/ingestion"
	"github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestRunProcessOrdersStartupServeAndCleanup(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	if err := RunProcess(context.Background(), validRuntimeConfig(), "test", dependencies); err != nil {
		t.Fatal(err)
	}
	want := []string{"open", "ping", "migrate", "store", "listen:tcp:127.0.0.1:8080", "serve", "listener-close", "database-close"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("process events = %#v, want %#v", events, want)
	}
}

func TestRunProcessClosesDatabaseAfterListenerOrServeFailure(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ProcessDependencies)
		message string
	}{
		{"listen", func(value *ProcessDependencies) {
			value.Listen = func(string, string) (net.Listener, error) { return nil, errors.New("listen failure") }
		}, "listen failure"},
		{"serve", func(value *ProcessDependencies) {
			value.Serve = func(context.Context, net.Listener, managedHTTPServer, Config) error {
				return errors.New("serve failure")
			}
		}, "serve failure"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			dependencies := processTestDependencies(&events)
			test.mutate(&dependencies)
			err := RunProcess(context.Background(), validRuntimeConfig(), "test", dependencies)
			if err == nil || !strings.Contains(err.Error(), test.message) || events[len(events)-1] != "database-close" {
				t.Fatalf("RunProcess() error = %v, events = %#v", err, events)
			}
		})
	}
}

func TestRunProcessPreservesServeAndDatabaseCloseErrors(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	dependencies.Serve = func(context.Context, net.Listener, managedHTTPServer, Config) error {
		return errors.New("serve failure")
	}
	dependencies.Database.Close = func(*sql.DB) error { return errors.New("close failure") }
	err := RunProcess(context.Background(), validRuntimeConfig(), "test", dependencies)
	if err == nil || !strings.Contains(err.Error(), "serve failure") || !strings.Contains(err.Error(), "close failure") {
		t.Fatalf("combined error = %v", err)
	}
}

func TestRunProcessStopsWhenRequestAuditSinkFails(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	dependencies.AuditSink = processFailingAuditSink{}
	dependencies.Serve = func(ctx context.Context, _ net.Listener, managed managedHTTPServer, _ Config) error {
		server := managed.(*http.Server)
		server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
		<-ctx.Done()
		return nil
	}
	err := RunProcess(context.Background(), validRuntimeConfig(), "test", dependencies)
	if err == nil || !strings.Contains(err.Error(), "audit storage unavailable") || events[len(events)-1] != "database-close" {
		t.Fatalf("audit failure result = %v, events = %#v", err, events)
	}
}

func TestRunProcessWiresCredentialWatcherAndAuditsResults(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	sink := &processRecordingAuditSink{}
	dependencies.AuditSink = sink
	dependencies.Serve = func(ctx context.Context, _ net.Listener, _ managedHTTPServer, _ Config) error {
		<-ctx.Done()
		return nil
	}
	dependencies.WatchCredentials = func(_ context.Context, registry *server.CredentialRegistry, path string, interval time.Duration, observer server.CredentialReloadObserver) error {
		if registry == nil || !filepath.IsAbs(path) || interval != 15*time.Second {
			t.Fatalf("watcher inputs = %v, %q, %s", registry, path, interval)
		}
		observer(server.CredentialReloadResult{OccurredAt: time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC), Succeeded: false, Err: errors.New("invalid update")})
		observer(server.CredentialReloadResult{OccurredAt: time.Date(2026, 8, 22, 10, 0, 1, 0, time.UTC), Succeeded: true})
		return nil
	}
	config := validRuntimeConfig()
	registry, err := server.NewCredentialRegistry([]server.BearerCredential{{ID: "process-reader", Token: "process-reader-token-0123456789abcdefgh", Scopes: []string{server.ScopeControlPlaneRead}}})
	if err != nil {
		t.Fatal(err)
	}
	config.CredentialRegistry = registry
	config.Authenticator, config.Authorizer, _ = registry.Security()
	config.CredentialID = ""
	config.CredentialIDs = config.Authenticator.CredentialIDs()
	config.CredentialFile = filepath.Join(t.TempDir(), "credentials.json")
	config.CredentialReloadInterval = 15 * time.Second
	if err := RunProcess(context.Background(), config, "test", dependencies); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 || sink.events[0].EventName != "opscustodian.credential.reload.completed" || sink.events[0].Attributes["opscustodian.credential.reload.result"] != "failed" || sink.events[1].Attributes["opscustodian.credential.reload.result"] != "succeeded" {
		t.Fatalf("reload audit events = %#v", sink.events)
	}
}

func TestRunProcessWiresRepositorySetSchedulerAndAuditsSummary(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	sink := &processRecordingAuditSink{}
	dependencies.AuditSink = sink
	dependencies.Serve = func(ctx context.Context, _ net.Listener, _ managedHTTPServer, _ Config) error {
		<-ctx.Done()
		return nil
	}
	root := t.TempDir()
	dependencies.LoadRepositorySet = func(path string) (ingestion.RepositorySet, error) {
		if !filepath.IsAbs(path) {
			t.Fatalf("repository set path = %q", path)
		}
		return ingestion.RepositorySet{
			Repositories: []ingestion.Repository{{Source: "github:acme/platform", Connector: ingestion.LocalConnectorName, Location: root, Revision: "abc123"}},
			Interval:     time.Minute, MaxJitter: time.Second, MaxConcurrency: 2, RepositoryTimeout: 30 * time.Second,
			Retry: ingestion.RetryPolicy{MaxAttempts: 1},
		}, nil
	}
	dependencies.RunIngestionScheduler = func(_ context.Context, scheduler ingestion.Scheduler) error {
		if len(scheduler.Repositories) != 1 || scheduler.Interval != time.Minute || scheduler.MaxJitter != time.Second {
			t.Fatalf("scheduler = %#v", scheduler)
		}
		return scheduler.Observer(ingestion.ScheduleObservation{
			StartedAt:  time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
			FinishedAt: time.Date(2026, 8, 22, 10, 0, 2, 0, time.UTC),
			Results:    []ingestion.Result{{Status: ingestion.StatusPersisted}, {Status: ingestion.StatusFailed}},
		})
	}
	config := validRuntimeConfig()
	config.RepositorySetFile = filepath.Join(t.TempDir(), "repositories.json")
	if err := RunProcess(context.Background(), config, "test", dependencies); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 || sink.events[0].EventName != "opscustodian.ingestion.schedule.completed" || sink.events[0].Attributes["opscustodian.ingestion.persisted.count"] != 1 || sink.events[0].Attributes["opscustodian.ingestion.failed.count"] != 1 {
		t.Fatalf("ingestion audit events = %#v", sink.events)
	}
}

func TestRunProcessRequiresAndBuildsGitHubAppAuthenticationBeforeDatabaseIO(t *testing.T) {
	var events []string
	dependencies := processTestDependencies(&events)
	dependencies.LoadRepositorySet = func(string) (ingestion.RepositorySet, error) {
		return ingestion.RepositorySet{
			Repositories: []ingestion.Repository{{Source: "github:acme/platform", Connector: ingestion.GitHubConnectorName, Ref: "main", CredentialReference: "github-app:installation:42"}},
			Interval:     time.Minute, MaxConcurrency: 1, RepositoryTimeout: time.Minute, Retry: ingestion.RetryPolicy{MaxAttempts: 1},
		}, nil
	}
	config := validRuntimeConfig()
	config.RepositorySetFile = filepath.Join(t.TempDir(), "repositories.json")
	if err := RunProcess(context.Background(), config, "test", dependencies); err == nil || !strings.Contains(err.Error(), "not configured") || len(events) != 0 {
		t.Fatalf("missing App configuration error = %v, events = %#v", err, events)
	}

	config.GitHubAppID = 1234
	config.GitHubAppPrivateKeyFile = filepath.Join(t.TempDir(), "app.pem")
	dependencies.LoadGitHubAppKey = func(path string) ([]byte, error) {
		if path != config.GitHubAppPrivateKeyFile {
			t.Fatalf("private key path = %q", path)
		}
		return []byte("private-key-material"), nil
	}
	dependencies.BuildGitHubAppProvider = func(options ingestion.GitHubAppProviderOptions) (ingestion.GitHubAppTokenProvider, error) {
		if options.AppID != 1234 || string(options.PrivateKeyPEM) != "private-key-material" || options.Observer == nil {
			t.Fatalf("provider options = %#v", options)
		}
		return processGitHubAppProvider{}, nil
	}
	dependencies.RunIngestionScheduler = func(context.Context, ingestion.Scheduler) error { return nil }
	if err := RunProcess(context.Background(), config, "test", dependencies); err != nil {
		t.Fatal(err)
	}
}

type processGitHubAppProvider struct{}

func (processGitHubAppProvider) InstallationToken(context.Context, int64) (ingestion.GitHubAppInstallationToken, error) {
	return ingestion.GitHubAppInstallationToken{}, errors.New("not called")
}

func TestRunProcessRejectsIncompleteProcessDependenciesBeforeDatabaseIO(t *testing.T) {
	opened := false
	database := successfulDependencies()
	database.Open = func(string) (*sql.DB, error) { opened = true; return &sql.DB{}, nil }
	if err := RunProcess(context.Background(), validRuntimeConfig(), "test", ProcessDependencies{Database: database}); err == nil || opened {
		t.Fatalf("incomplete process error = %v, opened = %v", err, opened)
	}
}

func TestDefaultProcessDependenciesAreCompleteWithoutStartingIO(t *testing.T) {
	dependencies, err := DefaultProcessDependencies()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDependencies(dependencies.Database); err != nil || dependencies.Listen == nil || dependencies.Serve == nil || dependencies.AuditSink == nil || dependencies.WatchCredentials == nil || dependencies.LoadRepositorySet == nil || dependencies.RunIngestionScheduler == nil || dependencies.CredentialEnvironment == nil || dependencies.LoadGitHubAppKey == nil || dependencies.BuildGitHubAppProvider == nil {
		t.Fatalf("default process dependencies are incomplete: %v", err)
	}
}

func processTestDependencies(events *[]string) ProcessDependencies {
	database := &sql.DB{}
	return ProcessDependencies{
		AuditSink: discardRequestAuditSink{},
		Database: Dependencies{
			Open:    func(string) (*sql.DB, error) { *events = append(*events, "open"); return database, nil },
			Ping:    func(context.Context, *sql.DB) error { *events = append(*events, "ping"); return nil },
			Migrate: func(context.Context, *sql.DB) error { *events = append(*events, "migrate"); return nil },
			BuildStore: func(*sql.DB, string, string) (SnapshotStore, error) {
				*events = append(*events, "store")
				return successfulDependenciesStore(), nil
			},
			Close: func(*sql.DB) error { *events = append(*events, "database-close"); return nil },
		},
		Listen: func(network, address string) (net.Listener, error) {
			*events = append(*events, "listen:"+network+":"+address)
			return &processTestListener{events: events}, nil
		},
		Serve: func(_ context.Context, listener net.Listener, _ managedHTTPServer, _ Config) error {
			*events = append(*events, "serve")
			return nil
		},
		WatchCredentials: func(context.Context, *server.CredentialRegistry, string, time.Duration, server.CredentialReloadObserver) error {
			return nil
		},
		LoadRepositorySet:     ingestion.LoadRepositorySet,
		RunIngestionScheduler: func(ctx context.Context, scheduler ingestion.Scheduler) error { return scheduler.Run(ctx) },
		CredentialEnvironment: func(string) (string, bool) { return "", false },
		LoadGitHubAppKey:      ingestion.LoadGitHubAppPrivateKey,
		BuildGitHubAppProvider: func(options ingestion.GitHubAppProviderOptions) (ingestion.GitHubAppTokenProvider, error) {
			return ingestion.NewGitHubAppProvider(options)
		},
	}
}

func successfulDependenciesStore() SnapshotStore { return store.NewMemory() }

type processTestListener struct{ events *[]string }

func (*processTestListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (listener *processTestListener) Close() error {
	*listener.events = append(*listener.events, "listener-close")
	return nil
}
func (*processTestListener) Addr() net.Addr { return fakeAddress("127.0.0.1:8080") }

type processFailingAuditSink struct{}

func (processFailingAuditSink) Record(context.Context, audit.Event) error {
	return errors.New("audit storage unavailable")
}

type processRecordingAuditSink struct{ events []audit.Event }

func (sink *processRecordingAuditSink) Record(_ context.Context, event audit.Event) error {
	sink.events = append(sink.events, event)
	return nil
}
