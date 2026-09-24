package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/ingestion"
	"github.com/opscustodian/opscustodian/internal/server"
)

type ProcessDependencies struct {
	Database               Dependencies
	Listen                 func(string, string) (net.Listener, error)
	Serve                  func(context.Context, net.Listener, managedHTTPServer, Config) error
	AuditSink              server.RequestAuditSink
	WatchCredentials       func(context.Context, *server.CredentialRegistry, string, time.Duration, server.CredentialReloadObserver) error
	LoadRepositorySet      func(string) (ingestion.RepositorySet, error)
	RunIngestionScheduler  func(context.Context, ingestion.Scheduler) error
	CredentialEnvironment  ingestion.EnvironmentLookup
	LoadGitHubAppKey       func(string) ([]byte, error)
	BuildGitHubAppProvider func(ingestion.GitHubAppProviderOptions) (ingestion.GitHubAppTokenProvider, error)
	NewSchedulerHolderID   func() (string, error)
}

const databaseReadinessInterval = 5 * time.Second

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
		WatchCredentials:      server.WatchCredentialFile,
		LoadRepositorySet:     ingestion.LoadRepositorySet,
		RunIngestionScheduler: func(ctx context.Context, scheduler ingestion.Scheduler) error { return scheduler.Run(ctx) },
		CredentialEnvironment: os.LookupEnv,
		LoadGitHubAppKey:      ingestion.LoadGitHubAppPrivateKey,
		BuildGitHubAppProvider: func(options ingestion.GitHubAppProviderOptions) (ingestion.GitHubAppTokenProvider, error) {
			return ingestion.NewGitHubAppProvider(options)
		},
		NewSchedulerHolderID: randomSchedulerHolderID,
	}, nil
}

func RunProcess(ctx context.Context, config Config, buildVersion string, dependencies ProcessDependencies) (resultErr error) {
	if dependencies.Listen == nil || dependencies.Serve == nil || dependencies.AuditSink == nil || dependencies.WatchCredentials == nil || dependencies.LoadRepositorySet == nil || dependencies.RunIngestionScheduler == nil || dependencies.CredentialEnvironment == nil || dependencies.LoadGitHubAppKey == nil || dependencies.BuildGitHubAppProvider == nil || dependencies.NewSchedulerHolderID == nil {
		return fmt.Errorf("complete control-plane process dependencies are required")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	var repositorySet ingestion.RepositorySet
	if config.RepositorySetFile != "" {
		var err error
		repositorySet, err = dependencies.LoadRepositorySet(config.RepositorySetFile)
		if err != nil {
			return fmt.Errorf("load ingestion repository set: %w", err)
		}
	}
	usesGitHubApp := repositorySetUsesGitHubApp(repositorySet)
	readiness := server.NewReadinessTracker(config.RepositorySetFile != "", usesGitHubApp)
	auditFailures := make(chan error, 1)
	githubAuthObserver := func(observationContext context.Context, observation ingestion.GitHubAuthObservation) error {
		githubStatus := server.ReadinessDegraded
		if observation.Result == ingestion.GitHubAuthResultHit || observation.Result == ingestion.GitHubAuthResultRefreshed || observation.Result == ingestion.GitHubAuthResultSucceeded {
			githubStatus = server.ReadinessReady
		}
		if err := readiness.Update(server.ReadinessGitHubAuth, githubStatus); err != nil {
			return err
		}
		event := audit.FromGitHubAuthentication(audit.GitHubAuthenticationObservation{
			OccurredAt: observation.OccurredAt, OrganizationID: config.OrganizationID,
			Operation: observation.Operation, Result: observation.Result, Transient: observation.Transient,
			HTTPStatus: observation.HTTPStatus, DurationMillis: observation.DurationMillis,
		})
		if err := dependencies.AuditSink.Record(observationContext, event); err != nil {
			auditErr := fmt.Errorf("record GitHub authentication audit: %w", err)
			select {
			case auditFailures <- auditErr:
			default:
			}
			return auditErr
		}
		return nil
	}
	var githubCredentials ingestion.CredentialResolver
	if config.RepositorySetFile != "" {
		environmentCredentials, err := ingestion.NewEnvironmentCredentialResolver(dependencies.CredentialEnvironment)
		if err != nil {
			return fmt.Errorf("initialize GitHub environment credential resolver: %w", err)
		}
		var appCredentials ingestion.CredentialResolver
		if usesGitHubApp {
			if config.GitHubAppID == 0 || config.GitHubAppPrivateKeyFile == "" {
				return fmt.Errorf("repository set requires GitHub App authentication but it is not configured")
			}
			privateKey, err := dependencies.LoadGitHubAppKey(config.GitHubAppPrivateKeyFile)
			if err != nil {
				return fmt.Errorf("load GitHub App private key: %w", err)
			}
			provider, err := dependencies.BuildGitHubAppProvider(ingestion.GitHubAppProviderOptions{AppID: config.GitHubAppID, PrivateKeyPEM: privateKey, Observer: githubAuthObserver})
			clear(privateKey)
			if err != nil {
				return fmt.Errorf("initialize GitHub App provider: %w", err)
			}
			appCredentials, err = ingestion.NewGitHubAppCredentialResolver(ingestion.GitHubAppCredentialOptions{Provider: provider, Observer: githubAuthObserver})
			if err != nil {
				return fmt.Errorf("initialize GitHub App credential resolver: %w", err)
			}
		}
		githubCredentials, err = ingestion.NewGitHubCredentialRouter(environmentCredentials, appCredentials)
		if err != nil {
			return fmt.Errorf("initialize GitHub credential router: %w", err)
		}
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
	if err := readiness.Update(server.ReadinessDatabase, server.ReadinessReady); err != nil {
		return err
	}
	persistentAuditSink, err := audit.NewMultiSink(dependencies.AuditSink, runtime.Store)
	if err != nil {
		return fmt.Errorf("initialize persistent audit sink: %w", err)
	}
	dependencies.AuditSink = persistentAuditSink
	var ingestionRunner ingestion.BatchRunner
	if config.RepositorySetFile != "" {
		revisions, err := ingestion.NewGitHubRevisionClient(ingestion.GitHubRevisionOptions{Credentials: githubCredentials})
		if err != nil {
			return fmt.Errorf("initialize GitHub revision client: %w", err)
		}
		archives, err := ingestion.NewGitHubArchiveClient(ingestion.GitHubArchiveHTTPOptions{Credentials: githubCredentials})
		if err != nil {
			return fmt.Errorf("initialize GitHub archive client: %w", err)
		}
		githubConnector, err := ingestion.NewGitHubConnector(revisions, archives)
		if err != nil {
			return fmt.Errorf("initialize GitHub connector: %w", err)
		}
		registry, err := ingestion.NewConnectorRegistry(ingestion.NewLocalConnector(), githubConnector)
		if err != nil {
			return fmt.Errorf("initialize ingestion connectors: %w", err)
		}
		ingestionRunner = ingestion.Orchestrator{
			Reader: runtime.Store, Writer: runtime.Store, Fetcher: registry,
			MaxConcurrency: repositorySet.MaxConcurrency, RepositoryTimeout: repositorySet.RepositoryTimeout, Retry: repositorySet.Retry,
		}
	}

	httpServer, err := NewControlPlaneHTTPServerWithReadinessAndPolicy(config, runtime.Store, buildVersion, dependencies.AuditSink, func(err error) {
		select {
		case auditFailures <- err:
		default:
		}
	}, readiness, newPolicyEvaluator(config))
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
	go monitorDatabaseReadiness(serveContext, runtime, readiness, databaseReadinessInterval, config.ConnectTimeout)
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
	var ingestionResult <-chan error
	if config.RepositorySetFile != "" {
		holderID, err := dependencies.NewSchedulerHolderID()
		if err != nil {
			return fmt.Errorf("generate ingestion scheduler holder ID: %w", err)
		}
		results := make(chan error, 1)
		ingestionResult = results
		go func() {
			results <- dependencies.RunIngestionScheduler(serveContext, ingestion.Scheduler{
				Runner: ingestionRunner, Repositories: repositorySet.Repositories,
				Interval: repositorySet.Interval, MaxJitter: repositorySet.MaxJitter,
				LeaseStore: runtime.Store, LeaseName: "repository-ingestion", HolderID: holderID,
				LeaseTTL: config.SchedulerLeaseTTL, RenewInterval: config.SchedulerRenewInterval,
				Observer: func(observation ingestion.ScheduleObservation) error {
					role := server.SchedulerRoleLeader
					if observation.Standby {
						role = server.SchedulerRoleStandby
					} else if observation.LeaseLost {
						role = server.SchedulerRoleLeaseLost
					}
					if err := readiness.Update(server.ReadinessSchedulerRole, role); err != nil {
						return err
					}
					ingestionStatus := server.ReadinessReady
					for _, result := range observation.Results {
						if result.Status == ingestion.StatusFailed || result.Status == ingestion.StatusConflict || result.Status == ingestion.StatusCancelled {
							ingestionStatus = server.ReadinessDegraded
							break
						}
					}
					if observation.Err != nil {
						ingestionStatus = server.ReadinessDegraded
					}
					if err := readiness.Update(server.ReadinessIngestion, ingestionStatus); err != nil {
						return err
					}
					event := ingestionScheduleAuditEvent(config.OrganizationID, observation)
					if err := dependencies.AuditSink.Record(serveContext, event); err != nil {
						return fmt.Errorf("record ingestion schedule audit: %w", err)
					}
					return nil
				},
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
	case ingestionErr := <-ingestionResult:
		cancelServe()
		serveErr := <-serveResult
		if ingestionErr != nil || serveErr != nil {
			return errors.Join(ingestionErr, serveErr)
		}
		return nil
	}
}

type databasePinger interface {
	Ping(context.Context) error
}

func monitorDatabaseReadiness(ctx context.Context, database databasePinger, readiness *server.ReadinessTracker, interval, timeout time.Duration) {
	if database == nil || readiness == nil || interval <= 0 || timeout <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingContext, cancel := context.WithTimeout(ctx, timeout)
			err := database.Ping(pingContext)
			cancel()
			status := server.ReadinessReady
			if err != nil {
				status = server.ReadinessDegraded
			}
			_ = readiness.Update(server.ReadinessDatabase, status)
		}
	}
}

func randomSchedulerHolderID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("read cryptographic entropy: %w", err)
	}
	return "process-" + hex.EncodeToString(value), nil
}

func repositorySetUsesGitHubApp(repositorySet ingestion.RepositorySet) bool {
	for _, repository := range repositorySet.Repositories {
		if _, err := ingestion.ParseGitHubAppCredentialReference(repository.CredentialReference); err == nil {
			return true
		}
	}
	return false
}

func ingestionScheduleAuditEvent(organizationID string, observation ingestion.ScheduleObservation) audit.Event {
	counts := map[string]int{}
	for _, result := range observation.Results {
		counts[result.Status]++
	}
	role := server.SchedulerRoleLeader
	if observation.Standby {
		role = server.SchedulerRoleStandby
	} else if observation.LeaseLost {
		role = server.SchedulerRoleLeaseLost
	}
	return audit.FromIngestionSchedule(audit.IngestionScheduleObservation{
		OccurredAt: observation.FinishedAt, OrganizationID: organizationID,
		DurationMillis:  max(observation.FinishedAt.Sub(observation.StartedAt).Milliseconds(), 0),
		RepositoryCount: len(observation.Results), PersistedCount: counts[ingestion.StatusPersisted],
		UnchangedCount: counts[ingestion.StatusUnchanged], ConflictCount: counts[ingestion.StatusConflict],
		FailedCount: counts[ingestion.StatusFailed], CancelledCount: counts[ingestion.StatusCancelled], Succeeded: observation.Err == nil,
		SchedulerRole: role,
	})
}

var _ managedHTTPServer = (*http.Server)(nil)
