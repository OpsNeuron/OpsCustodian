package ingestion

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitHubAppProviderSignsJWTAndRequestsInstallationToken(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	privateKey, privateKeyPEM := testGitHubAppPrivateKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		jwt := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		claims := verifyGitHubAppJWT(t, privateKey, jwt)
		if claims.Issuer != 1234 || claims.IssuedAt != now.Add(-time.Minute).Unix() || claims.ExpiresAt != now.Add(githubAppJWTLifetime).Unix() {
			t.Fatalf("unexpected JWT claims: %#v", claims)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		fmt.Fprintf(writer, `{"token":"installation-token","expires_at":%q,"permissions":{"contents":"read"}}`, now.Add(time.Hour).Format(time.RFC3339))
	}))
	defer server.Close()

	provider, err := NewGitHubAppProvider(GitHubAppProviderOptions{
		AppID: 1234, PrivateKeyPEM: privateKeyPEM, Endpoint: server.URL,
		AllowInsecure: true, Client: server.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.InstallationToken(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if token.Value != "installation-token" || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected token: %#v", token)
	}
}

func TestGitHubAppProviderClassifiesFailuresWithoutResponseBodyLeak(t *testing.T) {
	_, privateKeyPEM := testGitHubAppPrivateKey(t)
	for _, test := range []struct {
		name      string
		status    int
		transient bool
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "rate limited", status: http.StatusTooManyRequests, transient: true},
		{name: "server failure", status: http.StatusServiceUnavailable, transient: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				fmt.Fprint(writer, "provider-secret-detail")
			}))
			defer server.Close()
			provider, err := NewGitHubAppProvider(GitHubAppProviderOptions{AppID: 1234, PrivateKeyPEM: privateKeyPEM, Endpoint: server.URL, AllowInsecure: true, Client: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.InstallationToken(context.Background(), 42)
			if err == nil || strings.Contains(err.Error(), "provider-secret-detail") || isTransient(err) != test.transient {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestGitHubAppProviderRejectsUnsafeConfigurationAndResponses(t *testing.T) {
	_, privateKeyPEM := testGitHubAppPrivateKey(t)
	if _, err := NewGitHubAppProvider(GitHubAppProviderOptions{AppID: 0, PrivateKeyPEM: privateKeyPEM}); err == nil {
		t.Fatal("zero App ID unexpectedly accepted")
	}
	if _, err := NewGitHubAppProvider(GitHubAppProviderOptions{AppID: 1, PrivateKeyPEM: []byte("secret")}); err == nil {
		t.Fatal("invalid private key unexpectedly accepted")
	}
	if _, err := NewGitHubAppProvider(GitHubAppProviderOptions{AppID: 1, PrivateKeyPEM: privateKeyPEM, Endpoint: "http://api.github.test"}); err == nil {
		t.Fatal("insecure endpoint unexpectedly accepted")
	}

	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusCreated)
		fmt.Fprintf(writer, `{"token":"installation-token","expires_at":%q}`, now.Add(24*time.Hour).Format(time.RFC3339))
	}))
	defer server.Close()
	provider, _ := NewGitHubAppProvider(GitHubAppProviderOptions{AppID: 1, PrivateKeyPEM: privateKeyPEM, Endpoint: server.URL, AllowInsecure: true, Client: server.Client(), Now: func() time.Time { return now }})
	if _, err := provider.InstallationToken(context.Background(), 42); err == nil {
		t.Fatal("long-lived token response unexpectedly accepted")
	}
}

type testGitHubAppClaims struct {
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	Issuer    int64 `json:"iss"`
}

func verifyGitHubAppJWT(t *testing.T, privateKey *rsa.PrivateKey, value string) testGitHubAppClaims {
	t.Helper()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT shape")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("invalid JWT signature: %v", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims testGitHubAppClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func testGitHubAppPrivateKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return privateKey, content
}
