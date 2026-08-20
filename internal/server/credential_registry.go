package server

import (
	"fmt"
	"sync/atomic"
	"time"
)

type credentialSecuritySnapshot struct {
	authenticator BearerAuthenticator
	authorizer    ScopeAuthorizer
}

// CredentialRegistry atomically publishes immutable authentication and
// authorization snapshots so a request can never observe a partially applied
// credential reload.
type CredentialRegistry struct {
	snapshot atomic.Pointer[credentialSecuritySnapshot]
	now      func() time.Time
}

func NewCredentialRegistry(credentials []BearerCredential) (*CredentialRegistry, error) {
	return newCredentialRegistry(credentials, time.Now)
}

func newCredentialRegistry(credentials []BearerCredential, now func() time.Time) (*CredentialRegistry, error) {
	if now == nil {
		return nil, fmt.Errorf("credential registry clock is required")
	}
	registry := &CredentialRegistry{now: now}
	if err := registry.Reload(credentials); err != nil {
		return nil, err
	}
	return registry, nil
}

func (registry *CredentialRegistry) Reload(credentials []BearerCredential) error {
	if registry == nil || registry.now == nil {
		return fmt.Errorf("configured credential registry is required")
	}
	authenticator, authorizer, err := newBearerCredentialSecurity(credentials, registry.now)
	if err != nil {
		return err
	}
	registry.snapshot.Store(&credentialSecuritySnapshot{authenticator: authenticator, authorizer: authorizer})
	return nil
}

func (registry *CredentialRegistry) Security() (BearerAuthenticator, ScopeAuthorizer, error) {
	if registry == nil || registry.snapshot.Load() == nil {
		return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("configured credential registry is required")
	}
	return BearerAuthenticator{registry: registry}, ScopeAuthorizer{registry: registry}, nil
}
