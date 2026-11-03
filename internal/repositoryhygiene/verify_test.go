package repositoryhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyTrackedFilesAcceptsReviewedSourceAndFixtures(t *testing.T) {
	root := t.TempDir()
	writeHygieneFixture(t, root, "README.md", "# reviewed source\n")
	writeHygieneFixture(t, root, "examples/demo/agentbom.before.json", `{}`)
	writeHygieneFixture(t, root, "internal/report/testdata/findings.golden.sarif", `{}`)
	if err := VerifyTrackedFiles(root, []string{"README.md", "examples/demo/agentbom.before.json", "internal/report/testdata/findings.golden.sarif"}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTrackedFilesRejectsSensitiveAndGeneratedContent(t *testing.T) {
	tests := []struct {
		name, path, content, contains string
	}{
		{"private key", "docs/guide.md", "-----BEGIN " + "PRIVATE KEY-----", "private-key-marker"},
		{"local path", "README.md", `C:\` + `Users\operator\report.html`, "windows-user-path"},
		{"root artifact", "agentbom.current.json", `{}`, "generated-artifact-root"},
		{"presentation", "docs/PRESENTATION_FA.md", "draft", "local-presentation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeHygieneFixture(t, root, test.path, test.content)
			err := VerifyTrackedFiles(root, []string{test.path})
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("hygiene result = %v", err)
			}
		})
	}
}

func writeHygieneFixture(t *testing.T, root, name, content string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
