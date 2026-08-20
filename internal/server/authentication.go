package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

const (
	minimumBearerTokenBytes = 32
	maximumBearerTokenBytes = 4096
)

type BearerAuthenticator struct {
	digest     [sha256.Size]byte
	configured bool
}

func NewBearerAuthenticator(token string) (BearerAuthenticator, error) {
	if len(token) < minimumBearerTokenBytes || len(token) > maximumBearerTokenBytes {
		return BearerAuthenticator{}, fmt.Errorf("API bearer token must contain between %d and %d bytes", minimumBearerTokenBytes, maximumBearerTokenBytes)
	}
	if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return BearerAuthenticator{}, fmt.Errorf("API bearer token must not contain whitespace")
	}
	return BearerAuthenticator{digest: sha256.Sum256([]byte(token)), configured: true}, nil
}

func (authenticator BearerAuthenticator) Configured() bool { return authenticator.configured }

func (authenticator BearerAuthenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			setRequestAuthentication(request, "public")
			next.ServeHTTP(w, request)
			return
		}
		if !authenticator.authorized(request.Header.Values("Authorization")) {
			setRequestAuthentication(request, "rejected")
			w.Header().Set("WWW-Authenticate", `Bearer realm="opscustodian"`)
			writeError(w, http.StatusUnauthorized, "authentication-required", "valid bearer authentication is required")
			return
		}
		setRequestAuthentication(request, "authenticated")
		next.ServeHTTP(w, request)
	})
}

func (authenticator BearerAuthenticator) authorized(values []string) bool {
	if len(values) != 1 {
		return false
	}
	header := values[0]
	if len(header) <= len("Bearer ") || !strings.EqualFold(header[:len("Bearer")], "Bearer") || header[len("Bearer")] != ' ' {
		return false
	}
	token := header[len("Bearer "):]
	if len(token) < minimumBearerTokenBytes || len(token) > maximumBearerTokenBytes || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(authenticator.digest[:], digest[:]) == 1
}
