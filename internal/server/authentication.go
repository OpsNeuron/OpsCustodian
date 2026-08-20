package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

var credentialIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)

const (
	minimumBearerTokenBytes = 32
	maximumBearerTokenBytes = 4096
)

type BearerCredential struct {
	ID     string   `json:"id"`
	Token  string   `json:"token"`
	Scopes []string `json:"scopes"`
}
type bearerCredentialDigest struct {
	identity string
	digest   [sha256.Size]byte
}
type BearerAuthenticator struct{ credentials []bearerCredentialDigest }
type authenticatedIdentityContextKey struct{}

func NewBearerAuthenticator(token string) (BearerAuthenticator, error) {
	return NewIdentifiedBearerAuthenticator("legacy-api-token", token)
}

func NewIdentifiedBearerAuthenticator(identity, token string) (BearerAuthenticator, error) {
	authenticator, _, err := NewBearerCredentialSecurity([]BearerCredential{{ID: identity, Token: token, Scopes: []string{ScopeControlPlaneRead}}})
	return authenticator, err
}

func NewBearerCredentialSecurity(credentials []BearerCredential) (BearerAuthenticator, ScopeAuthorizer, error) {
	if len(credentials) == 0 || len(credentials) > 100 {
		return BearerAuthenticator{}, ScopeAuthorizer{}, fmt.Errorf("API credential count must be between 1 and 100")
	}
	authenticator := BearerAuthenticator{credentials: make([]bearerCredentialDigest, 0, len(credentials))}
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
		authenticator.credentials = append(authenticator.credentials, bearerCredentialDigest{identity: credential.ID, digest: digest})
	}
	return authenticator, ScopeAuthorizer{grants: grants}, nil
}

func validateBearerToken(token string) error {
	if len(token) < minimumBearerTokenBytes || len(token) > maximumBearerTokenBytes {
		return fmt.Errorf("API bearer token must contain between %d and %d bytes", minimumBearerTokenBytes, maximumBearerTokenBytes)
	}
	if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return fmt.Errorf("API bearer token must not contain whitespace")
	}
	return nil
}

func (authenticator BearerAuthenticator) Configured() bool { return len(authenticator.credentials) > 0 }
func (authenticator BearerAuthenticator) CredentialID() string {
	if len(authenticator.credentials) == 1 {
		return authenticator.credentials[0].identity
	}
	return ""
}
func (authenticator BearerAuthenticator) CredentialIDs() []string {
	identities := make([]string, 0, len(authenticator.credentials))
	for _, credential := range authenticator.credentials {
		identities = append(identities, credential.identity)
	}
	return identities
}

func (authenticator BearerAuthenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			setRequestAuthentication(request, "public")
			next.ServeHTTP(w, request)
			return
		}
		identity, ok := authenticator.authenticate(request.Header.Values("Authorization"))
		if !ok {
			setRequestAuthentication(request, "rejected")
			w.Header().Set("WWW-Authenticate", `Bearer realm="opscustodian"`)
			writeError(w, http.StatusUnauthorized, "authentication-required", "valid bearer authentication is required")
			return
		}
		setRequestAuthentication(request, "authenticated")
		setRequestIdentity(request, identity)
		*request = *request.WithContext(context.WithValue(request.Context(), authenticatedIdentityContextKey{}, identity))
		next.ServeHTTP(w, request)
	})
}

func (authenticator BearerAuthenticator) authenticate(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	header := values[0]
	if len(header) <= len("Bearer ") || !strings.EqualFold(header[:len("Bearer")], "Bearer") || header[len("Bearer")] != ' ' {
		return "", false
	}
	token := header[len("Bearer "):]
	if validateBearerToken(token) != nil {
		return "", false
	}
	digest := sha256.Sum256([]byte(token))
	identity, matched := "", 0
	for _, credential := range authenticator.credentials {
		comparison := subtle.ConstantTimeCompare(credential.digest[:], digest[:])
		if comparison == 1 {
			identity = credential.identity
		}
		matched |= comparison
	}
	return identity, matched == 1
}
