package ingestion

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeGitHubZIPExtractsSingleRootAndCleansUp(t *testing.T) {
	archive := githubTestZIP(t, map[string]githubZIPEntry{
		"acme-platform-abc123/":                         {directory: true},
		"acme-platform-abc123/.github/workflows/":       {directory: true},
		"acme-platform-abc123/.github/workflows/ci.yml": {content: "name: CI"},
	})
	checkout, err := MaterializeGitHubZIP(context.Background(), bytes.NewReader(archive), GitHubArchiveOptions{TemporaryDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	root := checkout.Root
	content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil || string(content) != "name: CI" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
	if err := checkout.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkout.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkout still exists: %v", err)
	}
}

func TestMaterializeGitHubZIPRejectsTraversalSymlinkAndMultipleRoots(t *testing.T) {
	tests := map[string]map[string]githubZIPEntry{
		"traversal":        {"root/../../escape": {content: "bad"}},
		"backslash":        {"root/..\\escape": {content: "bad"}},
		"symlink":          {"root/link": {content: "target", symlink: true}},
		"roots":            {"root/a": {content: "a"}, "other/b": {content: "b"}},
		"duplicate case":   {"root/File": {content: "a"}, "root/file": {content: "b"}},
		"alternate stream": {"root/file:secret": {content: "bad"}},
		"windows device":   {"root/CON.txt": {content: "bad"}},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			archive := githubTestZIP(t, entries)
			if checkout, err := MaterializeGitHubZIP(context.Background(), bytes.NewReader(archive), GitHubArchiveOptions{TemporaryDirectory: t.TempDir()}); err == nil {
				_ = checkout.Close()
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestMaterializeGitHubZIPEnforcesCompressedExtractedAndEntryLimits(t *testing.T) {
	archive := githubTestZIP(t, map[string]githubZIPEntry{"root/a": {content: strings.Repeat("a", 128)}, "root/b": {content: "b"}})
	for name, limits := range map[string]GitHubArchiveLimits{
		"compressed": {MaximumArchiveBytes: 10, MaximumExtractedBytes: 1024, MaximumEntries: 10},
		"extracted":  {MaximumArchiveBytes: 1024, MaximumExtractedBytes: 64, MaximumEntries: 10},
		"entries":    {MaximumArchiveBytes: 1024, MaximumExtractedBytes: 1024, MaximumEntries: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if checkout, err := MaterializeGitHubZIP(context.Background(), bytes.NewReader(archive), GitHubArchiveOptions{TemporaryDirectory: t.TempDir(), Limits: limits}); err == nil {
				_ = checkout.Close()
				t.Fatal("archive limit was not enforced")
			}
		})
	}
}

func TestMaterializeGitHubZIPHonorsCancellation(t *testing.T) {
	archive := githubTestZIP(t, map[string]githubZIPEntry{"root/file": {content: "safe"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if checkout, err := MaterializeGitHubZIP(ctx, bytes.NewReader(archive), GitHubArchiveOptions{TemporaryDirectory: t.TempDir()}); !errors.Is(err, context.Canceled) {
		if checkout != nil {
			_ = checkout.Close()
		}
		t.Fatalf("cancellation error = %v", err)
	}
}

type githubZIPEntry struct {
	content   string
	directory bool
	symlink   bool
}

func githubTestZIP(t *testing.T, entries map[string]githubZIPEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, entry := range entries {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if entry.directory {
			header.Name = strings.TrimSuffix(name, "/") + "/"
			header.SetMode(os.ModeDir | 0o700)
		} else if entry.symlink {
			header.SetMode(os.ModeSymlink | 0o777)
		} else {
			header.SetMode(0o600)
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
