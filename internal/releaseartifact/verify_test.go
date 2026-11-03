package releaseartifact

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestVerifyDirectoryAcceptsCompleteReleaseSet(t *testing.T) {
	directory := createReleaseFixture(t, "v0.6.0-beta.1", "reviewed security policy")
	if err := VerifyDirectory(directory, "v0.6.0-beta.1"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDirectoryRejectsTamperAndSensitiveMetadata(t *testing.T) {
	t.Run("checksum tamper", func(t *testing.T) {
		directory := createReleaseFixture(t, "v0.6.0-beta.1", "reviewed security policy")
		path := filepath.Join(directory, "opscustodian.cdx.json")
		if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}],"tampered":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyDirectory(directory, "v0.6.0-beta.1"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("tampered release result = %v", err)
		}
	})

	t.Run("private key marker", func(t *testing.T) {
		directory := createReleaseFixture(t, "v0.6.0-beta.1", "-----BEGIN "+"PRIVATE KEY-----")
		if err := VerifyDirectory(directory, "v0.6.0-beta.1"); err == nil || !strings.Contains(err.Error(), "possible private key") {
			t.Fatalf("sensitive release result = %v", err)
		}
	})
}

func createReleaseFixture(t *testing.T, tag, security string) string {
	t.Helper()
	directory := t.TempDir()
	names, err := ExpectedAssetNames(tag)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		filename := filepath.Join(directory, name)
		switch {
		case strings.HasSuffix(name, ".tar.gz"):
			writeTarFixture(t, filename, strings.TrimSuffix(name, ".tar.gz"), security)
		case strings.HasSuffix(name, ".zip"):
			writeZIPFixture(t, filename, strings.TrimSuffix(name, ".zip"), security)
		case name == "opscustodian.cdx.json":
			if err := os.WriteFile(filename, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"application","name":"opscustodian"}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeChecksumFixture(t, directory, names)
	return directory
}

func archiveFixtureFiles(root, security string) map[string]string {
	binary := "opscustodian"
	if strings.Contains(root, "_windows_") {
		binary += ".exe"
	}
	return map[string]string{
		root + "/" + binary:   "binary-placeholder",
		root + "/README.md":   "# OpsCustodian\n",
		root + "/SECURITY.md": security,
		root + "/LICENSE":     "Apache License 2.0",
	}
}

func writeTarFixture(t *testing.T, filename, root, security string) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	for name, content := range archiveFixtureFiles(root, security) {
		header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}
		if strings.HasSuffix(name, "/opscustodian") {
			header.Mode = 0o755
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZIPFixture(t *testing.T, filename, root, security string) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for name, content := range archiveFixtureFiles(root, security) {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksumFixture(t *testing.T, directory string, names []string) {
	t.Helper()
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	if err := os.WriteFile(filepath.Join(directory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
