package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReloadCredentialFilePublishesValidatedSnapshotAndPreservesLastGood(t *testing.T) {
	oldToken := "file-old-token-0123456789abcdefghijklmnop"
	newToken := "file-new-token-0123456789abcdefghijklmnop"
	registry, err := NewCredentialRegistry([]BearerCredential{{ID: "old-reader", Token: oldToken, Scopes: []string{ScopeInventoryRead}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	valid := `[{"id":"new-reader","token":"` + newToken + `","scopes":["findings:read"]}]`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadCredentialFile(registry, path); err != nil {
		t.Fatal(err)
	}
	authenticator, _, _ := registry.Security()
	if identity, ok := authenticator.authenticate([]string{"Bearer " + newToken}); !ok || identity != "new-reader" {
		t.Fatalf("new credential = %q, %v", identity, ok)
	}

	if err := os.WriteFile(path, []byte(`[{"id":"broken"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadCredentialFile(registry, path); err == nil {
		t.Fatal("invalid file reload succeeded")
	}
	if identity, ok := authenticator.authenticate([]string{"Bearer " + newToken}); !ok || identity != "new-reader" {
		t.Fatal("invalid reload replaced last-known-good snapshot")
	}
}

func TestCredentialFileRejectsUnsafeSources(t *testing.T) {
	registry, _ := NewCredentialRegistry([]BearerCredential{{ID: "safe-reader", Token: "safe-source-token-0123456789abcdefghijkl", Scopes: []string{ScopeInventoryRead}}})
	directory := t.TempDir()
	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", int(MaximumCredentialFileBytes+1))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadCredentialFile(registry, oversized); err == nil {
		t.Fatal("oversized file accepted")
	}
	if err := ReloadCredentialFile(registry, directory); err == nil {
		t.Fatal("directory accepted")
	}

	if runtime.GOOS != "windows" {
		permissive := filepath.Join(directory, "permissive.json")
		if err := os.WriteFile(permissive, []byte(`[]`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(permissive, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ReloadCredentialFile(registry, permissive); err == nil {
			t.Fatal("permissive file accepted")
		}
	}
}

func TestParseBearerCredentialsJSONIsStrict(t *testing.T) {
	for _, content := range []string{
		`[{"id":"reader","token":"token-token-token-token-token-token-12","scopes":["inventory:read"],"unknown":true}]`,
		`[] []`,
		`not-json`,
	} {
		if _, err := ParseBearerCredentialsJSON([]byte(content)); err == nil {
			t.Fatalf("invalid credential JSON accepted: %s", content)
		}
	}
}
