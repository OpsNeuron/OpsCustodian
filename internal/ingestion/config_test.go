package ingestion

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRepositorySetBuildsRuntimeConfiguration(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	content := repositorySetJSON(root, "")
	config, err := ParseRepositorySet([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if config.Interval != time.Minute || config.MaxJitter != 5*time.Second || config.MaxConcurrency != 2 || config.RepositoryTimeout != 30*time.Second || config.Retry.MaxAttempts != 3 {
		t.Fatalf("schedule = %#v", config)
	}
	if len(config.Repositories) != 1 || config.Repositories[0].Location != root || config.Repositories[0].Boundaries[0] != ".github=automation" {
		t.Fatalf("repositories = %#v", config.Repositories)
	}
}

func TestParseRepositorySetRejectsUnknownSecretAndTrailingJSON(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	for name, content := range map[string]string{
		"secret field": repositorySetJSON(root, `,"token":"do-not-store"`),
		"trailing":     repositorySetJSON(root, "") + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRepositorySet([]byte(content)); err == nil {
				t.Fatal("unsafe repository set was accepted")
			}
		})
	}
}

func TestParseRepositorySetRejectsDuplicateAndUnsafeRepository(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	duplicate := strings.Replace(repositorySetJSON(root, ""), `]}`, `,{"source":"github:acme/platform","connector":"local","location":`+fmt.Sprintf("%q", root)+`,"revision":"def456"}]}`, 1)
	if _, err := ParseRepositorySet([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate result = %v", err)
	}
	unsafe := strings.Replace(repositorySetJSON(root, ""), fmt.Sprintf("%q", root), `"."`, 1)
	if _, err := ParseRepositorySet([]byte(unsafe)); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("unsafe location result = %v", err)
	}
}

func TestLoadRepositorySetRequiresBoundedRegularAbsoluteFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "repositories.json")
	if err := os.WriteFile(path, []byte(repositorySetJSON(filepath.Clean(directory), "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRepositorySet(filepath.Clean(path)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRepositorySet("repositories.json"); err == nil {
		t.Fatal("relative repository set path was accepted")
	}
}

func repositorySetJSON(root, repositoryExtra string) string {
	return fmt.Sprintf(`{"apiVersion":"%s","kind":"%s","schedule":{"interval":"1m","maxJitter":"5s","maxConcurrency":2,"repositoryTimeout":"30s","retry":{"maxAttempts":3,"initialBackoff":"1s","maxBackoff":"10s"}},"repositories":[{"source":"github:acme/platform","connector":"local","location":%q,"revision":"abc123","boundaries":[".github=automation"],"maxFileSize":2097152%s}]}`, RepositorySetAPIVersion, RepositorySetKind, root, repositoryExtra)
}
