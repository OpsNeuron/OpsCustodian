package ingestion

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadGitHubAppPrivateKeyReadsBoundedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, []byte("private-key-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := LoadGitHubAppPrivateKey(path)
	if err != nil || string(content) != "private-key-content" {
		t.Fatalf("LoadGitHubAppPrivateKey() = %q, %v", content, err)
	}
}

func TestLoadGitHubAppPrivateKeyRejectsUnsafeSources(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadGitHubAppPrivateKey(root); err == nil {
		t.Fatal("directory unexpectedly accepted")
	}
	oversized := filepath.Join(root, "oversized.pem")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", int(MaximumGitHubAppPrivateKeyBytes+1))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGitHubAppPrivateKey(oversized); err == nil {
		t.Fatal("oversized key unexpectedly accepted")
	}
	if runtime.GOOS != "windows" {
		permissive := filepath.Join(root, "permissive.pem")
		if err := os.WriteFile(permissive, []byte("key"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadGitHubAppPrivateKey(permissive); err == nil {
			t.Fatal("permissive key unexpectedly accepted")
		}
	}
}
