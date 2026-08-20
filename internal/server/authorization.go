package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const (
	ScopeControlPlaneRead = "control-plane:read"
	ScopeContractsRead    = "contracts:read"
	ScopeInventoryRead    = "inventory:read"
	ScopeFindingsRead     = "findings:read"
)

var supportedScopes = map[string]struct{}{
	ScopeControlPlaneRead: {},
	ScopeContractsRead:    {},
	ScopeInventoryRead:    {},
	ScopeFindingsRead:     {},
}

type ScopeAuthorizer struct {
	scopes map[string]struct{}
}

func NewScopeAuthorizer(scopes []string) (ScopeAuthorizer, error) {
	if len(scopes) == 0 {
		return ScopeAuthorizer{}, fmt.Errorf("at least one API authorization scope is required")
	}
	granted := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, ok := supportedScopes[scope]; !ok {
			return ScopeAuthorizer{}, fmt.Errorf("unsupported API authorization scope %q", scope)
		}
		granted[scope] = struct{}{}
	}
	return ScopeAuthorizer{scopes: granted}, nil
}

func (authorizer ScopeAuthorizer) Configured() bool { return len(authorizer.scopes) > 0 }

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
		required := requiredScope(request.URL.Path)
		_, broad := authorizer.scopes[ScopeControlPlaneRead]
		_, specific := authorizer.scopes[required]
		if !broad && !specific {
			setRequestAuthorization(request, "denied")
			writeError(w, http.StatusForbidden, "authorization-denied", "the authenticated identity is not authorized for this operation")
			return
		}
		setRequestAuthorization(request, "authorized")
		next.ServeHTTP(w, request)
	})
}

func requiredScope(path string) string {
	switch {
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
