package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

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
	if err := validateDependencies(dependencies.Database); err != nil || dependencies.Listen == nil || dependencies.Serve == nil {
		t.Fatalf("default process dependencies are incomplete: %v", err)
	}
}

func processTestDependencies(events *[]string) ProcessDependencies {
	database := &sql.DB{}
	return ProcessDependencies{
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
