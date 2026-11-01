package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var credentialIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)

const (
	minimumBearerTokenBytes = 32
	maximumBearerTokenBytes = 4096
)

type BearerCredential struct {
	ID           string   `json:"id"`
	Token        string   `json:"token"`
	Scopes       []string `json:"scopes"`
	Repositories []string `json:"repositories,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
	NotBefore    string   `json:"notBefore,omitempty"`
	ExpiresAt    string   `json:"expiresAt,omitempty"`
}
type bearerCredentialDigest struct {
	identity     string
	digest       [sha256.Size]byte
	repositories map[string]struct{}
	restricted   bool
	disabled     bool
	notBefore    time.Time
	expiresAt    time.Time
}
type BearerAuthenticator struct {
	credentials []bearerCredentialDigest
	now         func() time.Time
	registry    *CredentialRegistry
}
type authenticatedIdentityContextKey struct{}
type authenticatedPrincipal struct {
	identity     string
	scopes       map[string]struct{}
	repositories map[string]struct{}
	restricted   bool
}

func NewBearerAuthenticator(token string) (BearerAuthenticator, error) {
	return NewIdentifiedBearerAuthenticator("legacy-api-token", token)
}

func NewIdentifiedBearerAuthenticator(identity, token string) (BearerAuthenticator, error) {
	authenticator, _, err := NewBearerCredentialSecurity([]BearerCredential{{ID: identity, Token: token, Scopes: []string{ScopeControlPlaneRead}}})
	return authenticator, err
}

func NewBearerCredentialSecurity(credentials []BearerCredential) (BearerAuthenticator, ScopeAuthorizer, error) {
	return newBearerCredentialSecurity(credentials, time.Now)
}

func newBearerCredentialSecurity(credentials []BearerCredential, now func() time.Time) (BearerAuthenticator, ScopeAuthorizer, error) {
	if len(credentials) == 0 || len(credentials) > 100 {
		return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("API credential count must be between 1 and 100")
	}
	if now == nil {
		return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("credential clock is required")
	}
	authenticator := BearerAuthenticator{credentials: make([]bearerCredentialDigest, 0, len(credentials)), now: now}
	grants := make(map[string]map[string]struct{}, len(credentials))
	digests := make(map[[sha256.Size]byte]struct{}, len(credentials))
	for _, credential := range credentials {
		if _, exists := grants[credential.ID]; exists {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("duplicate API credential ID %q", credential.ID)
		}
		if !credentialIDPattern.MatchString(credential.ID) {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("API credential ID must contain 3 to 63 lowercase letters, digits, or hyphens and start with a letter")
		}
		if err := validateBearerToken(credential.Token); err != nil {
			return BearerAuthenticator{}, ScopeAuthorizer{}, err
		}
		digest := sha256.Sum256([]byte(credential.Token))
		if _, exists := digests[digest]; exists {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("API bearer tokens must be unique")
		}
		digests[digest] = struct{}{}
		scopes, err := validatedScopes(credential.Scopes)
		if err != nil {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("credential %q: %w", credential.ID, err)
		}
		grants[credential.ID] = scopes
		repositories, err := validatedRepositoryGrants(credential.Repositories)
		if err != nil {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("credential %q: %w", credential.ID, err)
		}
		notBefore, err := parseCredentialTime(credential.ID, "notBefore", credential.NotBefore)
		if err != nil {
			return BearerAuthenticator{}, ScopeAuthorizer{}, err
		}
		expiresAt, err := parseCredentialTime(credential.ID, "expiresAt", credential.ExpiresAt)
		if err != nil {
			return BearerAuthenticator{}, ScopeAuthorizer{}, err
		}
		if !notBefore.IsZero() && !expiresAt.IsZero() && !expiresAt.After(notBefore) {
			return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("credential %q expiresAt must be after notBefore", credential.ID)
		}
		authenticator.credentials = append(authenticator.credentials, bearerCredentialDigest{identity: credential.ID, digest: digest, repositories: repositories, restricted: len(credential.Repositories) > 0, disabled: credential.Disabled, notBefore: notBefore, expiresAt: expiresAt})
	}
	return authenticator, ScopeAuthorizer{grants: grants}, nil
}

func parseCredentialTime(identity, field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("credential %q %s must be RFC3339", identity, field)
	}
	return parsed.UTC(), nil
}

func validateBearerToken(token string) error {
	if len(token) < minimumBearerTokenBytes || len(token) > maximumBearerTokenBytes {
		return fmt.Errorf("API bearer token must contain between %d and %d bytes", minimumBearerTokenBytes, maximumBearerTokenBytes)
	}
	padding := false
	for _, value := range []byte(token) {
		if value == '=' {
			padding = true
			continue
		}
		if padding || !validBearerTokenByte(value) {
			return fmt.Errorf("API bearer token contains invalid characters")
		}
	}
	return nil
}

func validBearerTokenByte(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' ||
		strings.ContainsRune("-._~+/", rune(value))
}

func (authenticator BearerAuthenticator) Configured() bool {
	return len(authenticator.credentials) > 0 || (authenticator.registry != nil && authenticator.registry.snapshot.Load() != nil)
}
func (authenticator BearerAuthenticator) CredentialID() string {
	if authenticator.registry != nil {
		return authenticator.registry.snapshot.Load().authenticator.CredentialID()
	}
	if len(authenticator.credentials) == 1 {
		return authenticator.credentials[0].identity
	}
	return ""
}
func (authenticator BearerAuthenticator) CredentialIDs() []string {
	if authenticator.registry != nil {
		return authenticator.registry.snapshot.Load().authenticator.CredentialIDs()
	}
	identities := make([]string, 0, len(authenticator.credentials))
	for _, credential := range authenticator.credentials {
		identities = append(identities, credential.identity)
	}
	return identities
}

func (authenticator BearerAuthenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" || request.URL.Path == "/readyz" {
			setRequestAuthentication(request, "public")
			next.ServeHTTP(w, request)
			return
		}
		principal, ok := authenticator.authenticatePrincipal(request.Header.Values("Authorization"))
		if !ok {
			setRequestAuthentication(request, "rejected")
			w.Header().Set("WWW-Authenticate", `Bearer realm="opscustodian"`)
			writeError(w, http.StatusUnauthorized, "authentication-required", "valid bearer authentication is required")
			return
		}
		setRequestAuthentication(request, "authenticated")
		setRequestIdentity(request, principal.identity)
		*request = *request.WithContext(context.WithValue(request.Context(), authenticatedIdentityContextKey{}, principal))
		next.ServeHTTP(w, request)
	})
}

func (authenticator BearerAuthenticator) authenticatePrincipal(values []string) (authenticatedPrincipal, bool) {
	if authenticator.registry != nil {
		snapshot := authenticator.registry.snapshot.Load()
		if snapshot == nil {
			return authenticatedPrincipal{}, false
		}
		principal, ok := snapshot.authenticator.authenticateLocalPrincipal(values)
		if !ok {
			return authenticatedPrincipal{}, false
		}
		principal.scopes = snapshot.authorizer.grants[principal.identity]
		return principal, true
	}
	return authenticator.authenticateLocalPrincipal(values)
}

func (authenticator BearerAuthenticator) authenticate(values []string) (string, bool) {
	if authenticator.registry != nil {
		snapshot := authenticator.registry.snapshot.Load()
		if snapshot == nil {
			return "", false
		}
		return snapshot.authenticator.authenticate(values)
	}
	principal, ok := authenticator.authenticateLocalPrincipal(values)
	return principal.identity, ok
}

func (authenticator BearerAuthenticator) authenticateLocalPrincipal(values []string) (authenticatedPrincipal, bool) {
	if len(values) != 1 {
		return authenticatedPrincipal{}, false
	}
	header := values[0]
	if len(header) <= len("Bearer ") || !strings.EqualFold(header[:len("Bearer")], "Bearer") || header[len("Bearer")] != ' ' {
		return authenticatedPrincipal{}, false
	}
	token := header[len("Bearer "):]
	if validateBearerToken(token) != nil {
		return authenticatedPrincipal{}, false
	}
	digest := sha256.Sum256([]byte(token))
	principal, matched := authenticatedPrincipal{}, 0
	now := authenticator.now().UTC()
	for _, credential := range authenticator.credentials {
		comparison := subtle.ConstantTimeCompare(credential.digest[:], digest[:])
		active := !credential.disabled && (credential.notBefore.IsZero() || !now.Before(credential.notBefore)) && (credential.expiresAt.IsZero() || now.Before(credential.expiresAt))
		if comparison == 1 && active {
			principal = authenticatedPrincipal{identity: credential.identity, repositories: credential.repositories, restricted: credential.restricted}
		}
		if active {
			matched |= comparison
		}
	}
	return principal, matched == 1
}

func validatedRepositoryGrants(repositoryIDs []string) (map[string]struct{}, error) {
	if len(repositoryIDs) > 1000 {
		return nil, fmt.Errorf("repository grant count must not exceed 1000")
	}
	if len(repositoryIDs) == 0 {
		return nil, nil
	}
	grants := make(map[string]struct{}, len(repositoryIDs))
	for _, repositoryID := range repositoryIDs {
		repositoryID = strings.TrimSpace(repositoryID)
		if !validRepositoryID(repositoryID) {
			return nil, fmt.Errorf("repository grant %q is not a valid repository ID", repositoryID)
		}
		if _, exists := grants[repositoryID]; exists {
			return nil, fmt.Errorf("duplicate repository grant %q", repositoryID)
		}
		grants[repositoryID] = struct{}{}
	}
	return grants, nil
}
