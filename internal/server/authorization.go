package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const (
	ScopeControlPlaneRead  = "control-plane:read"
	ScopeControlPlaneAdmin = "control-plane:admin"
	ScopeContractsRead     = "contracts:read"
	ScopeInventoryRead     = "inventory:read"
	ScopeFindingsRead      = "findings:read"
	ScopeSnapshotsWrite    = "snapshots:write"
)

var supportedScopes = map[string]struct{}{
	ScopeControlPlaneRead:  {},
	ScopeControlPlaneAdmin: {},
	ScopeContractsRead:     {},
	ScopeInventoryRead:     {},
	ScopeFindingsRead:      {},
	ScopeSnapshotsWrite:    {},
}

type ScopeAuthorizer struct {
	scopes   map[string]struct{}
	grants   map[string]map[string]struct{}
	registry *CredentialRegistry
}

func NewScopeAuthorizer(scopes []string) (ScopeAuthorizer, error) {
	if len(scopes) == 0 {
		return ScopeAuthorizer{}, fmt.Errorf("at least one API authorization scope is required")
	}
	granted, err := validatedScopes(scopes)
	if err != nil {
		return ScopeAuthorizer{}, err
	}
	return ScopeAuthorizer{scopes: granted}, nil
}

func validatedScopes(scopes []string) (map[string]struct{}, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("at least one API authorization scope is required")
	}
	granted := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, ok := supportedScopes[scope]; !ok {
			return nil, fmt.Errorf("unsupported API authorization scope %q", scope)
		}
		granted[scope] = struct{}{}
	}
	return granted, nil
}

func (authorizer ScopeAuthorizer) Configured() bool {
	return len(authorizer.scopes) > 0 || len(authorizer.grants) > 0 || (authorizer.registry != nil && authorizer.registry.snapshot.Load() != nil)
}

func (authorizer ScopeAuthorizer) Scopes() []string {
	values := make([]string, 0, len(authorizer.scopes))
	for scope := range authorizer.scopes {
		values = append(values, scope)
	}
	sort.Strings(values)
	return values
}

func (authorizer ScopeAuthorizer) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			setRequestAuthorization(request, "public")
			next.ServeHTTP(w, request)
			return
		}
		required := requiredScope(request.Method, request.URL.Path)
		if principal, ok := request.Context().Value(authenticatedIdentityContextKey{}).(authenticatedPrincipal); ok && principal.scopes != nil {
			authorizer = ScopeAuthorizer{scopes: principal.scopes}
		} else if authorizer.registry != nil {
			snapshot := authorizer.registry.snapshot.Load()
			if snapshot == nil {
				setRequestAuthorization(request, "denied")
				writeError(w, http.StatusForbidden, "authorization-denied", "the authenticated identity is not authorized for this operation")
				return
			}
			authorizer = snapshot.authorizer
		}
		scopes := authorizer.scopes
		if principal, ok := request.Context().Value(authenticatedIdentityContextKey{}).(authenticatedPrincipal); ok && authorizer.grants != nil {
			scopes = authorizer.grants[principal.identity]
		}
		_, broad := scopes[ScopeControlPlaneRead]
		_, admin := scopes[ScopeControlPlaneAdmin]
		_, specific := scopes[required]
		broadRead := broad && required != ScopeSnapshotsWrite
		if !admin && !broadRead && !specific {
			setRequestAuthorization(request, "denied")
			writeError(w, http.StatusForbidden, "authorization-denied", "the authenticated identity is not authorized for this operation")
			return
		}
		setRequestAuthorization(request, "authorized")
		next.ServeHTTP(w, request)
	})
}

func requiredScope(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/api/v1/snapshots":
		return ScopeSnapshotsWrite
	case path == "/api/v1/contracts":
		return ScopeContractsRead
	case path == "/api/v1/findings", path == "/api/v1/finding-lifecycles":
		return ScopeFindingsRead
	case strings.HasPrefix(path, "/api/v1/repositories"):
		return ScopeInventoryRead
	default:
		return ScopeControlPlaneRead
	}
}
