package repositoryhygiene

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maximumTrackedTextBytes = 8 << 20

var (
	generatedRootArtifact = regexp.MustCompile(`(?i)^(?:agentbom.*\.(?:json|ya?ml)|opscustodian.*\.(?:html|json)|drift.*\.(?:json|txt)|findings.*\.txt|license-report\.csv|.*\.sarif|.*\.jsonl|coverage\.out|.*\.prof)$`)
	contentRules          = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"private-key-marker", regexp.MustCompile("-----BEGIN " + `[A-Z0-9 ]*PRIVATE KEY-----`)},
		{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
		{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"aws-signed-url", regexp.MustCompile(`(?i)[?&]X-Amz-Signature=[0-9a-f]{32,}`)},
		{"google-signed-url", regexp.MustCompile(`(?i)[?&]X-Goog-Signature=[0-9a-f]{32,}`)},
		{"windows-user-path", regexp.MustCompile(`(?i)[A-Z]:\\Users\\[^\\\s]+\\`)},
		{"unix-user-path", regexp.MustCompile(`(?:/home|/Users)/[^/\s]+/`)},
	}
	binaryExtensions = map[string]struct{}{
		".gif": {}, ".ico": {}, ".jpeg": {}, ".jpg": {}, ".pdf": {}, ".png": {}, ".webp": {},
	}
)

// VerifyTrackedFiles scans only paths already selected by the caller's source
// control manifest. It never reports matching content, only a bounded rule and
// repository-relative path.
func VerifyTrackedFiles(root string, tracked []string) error {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("repository root is unavailable")
	}
	if len(tracked) == 0 {
		return fmt.Errorf("tracked-file manifest is empty")
	}
	seen := make(map[string]struct{}, len(tracked))
	for _, raw := range tracked {
		name := strings.ReplaceAll(raw, "\\", "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("tracked-file manifest contains an unsafe path")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("tracked-file manifest contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		if !strings.Contains(name, "/") && generatedRootArtifact.MatchString(name) {
			return fmt.Errorf("tracked path %q violates generated-artifact-root", name)
		}
		if name == "docs/PRESENTATION_FA.md" {
			return fmt.Errorf("tracked path %q violates local-presentation", name)
		}
		if _, binary := binaryExtensions[strings.ToLower(filepath.Ext(name))]; binary {
			continue
		}
		filename := filepath.Join(absolute, filepath.FromSlash(name))
		link, err := os.Lstat(filename)
		if err != nil {
			return fmt.Errorf("inspect tracked path %q: %w", name, err)
		}
		if !link.Mode().IsRegular() {
			return fmt.Errorf("tracked path %q is not a regular file", name)
		}
		if link.Size() > maximumTrackedTextBytes {
			return fmt.Errorf("tracked text path %q exceeds the hygiene bound", name)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read tracked path %q: %w", name, err)
		}
		if !utf8.Valid(content) || strings.IndexByte(string(content), 0) >= 0 {
			return fmt.Errorf("tracked path %q is unexpected binary content", name)
		}
		for _, rule := range contentRules {
			if rule.pattern.Match(content) {
				return fmt.Errorf("tracked path %q violates %s", name, rule.name)
			}
		}
	}
	return nil
}
