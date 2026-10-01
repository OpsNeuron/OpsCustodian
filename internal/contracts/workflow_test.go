package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$`)
var semanticVersion = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)

func TestGitHubWorkflowsUsePinnedActionsAndBoundedPermissions(t *testing.T) {
	root := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{
		"codeql.yml":             false,
		"container-security.yml": false,
		"ci.yml":                 false,
		"license-scan.yml":       false,
		"release.yml":            false,
		"vulnerability-scan.yml": false,
	}
	if len(entries) != len(expected) {
		t.Fatalf("workflow count = %d, expected %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			t.Fatalf("unexpected workflow %s", entry.Name())
		}
		expected[entry.Name()] = true
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if strings.Contains(text, "pull_request_target") || !strings.Contains(text, "permissions:\n  contents: read") {
			t.Fatalf("workflow %s has unsafe trigger or root permissions", entry.Name())
		}
		var document any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		var actions []string
		collectWorkflowActions(document, &actions)
		if len(actions) == 0 {
			t.Fatalf("workflow %s contains no actions", entry.Name())
		}
		for _, action := range actions {
			if !pinnedAction.MatchString(action) {
				t.Errorf("workflow %s action is not pinned to a full SHA: %s", entry.Name(), action)
			}
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected workflow %s was not found", name)
		}
	}
}

func TestCodeQLWorkflowKeepsReviewedSecurityCoverage(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"security-events: write",
		"language: go",
		"build-mode: autobuild",
		"language: actions",
		"build-mode: none",
		"queries: security-extended",
		"github/codeql-action/init@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
		"github/codeql-action/autobuild@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
		"github/codeql-action/analyze@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("CodeQL workflow is missing reviewed contract %q", required)
		}
	}
	if strings.Contains(text, "continue-on-error") {
		t.Fatal("CodeQL workflow weakens the blocking analysis gate")
	}
}

func TestCIExercisesEverySupportedDesktopPlatform(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"runs-on: ubuntu-latest",
		"runs-on: windows-latest",
		"runs-on: macos-latest",
		"name: Linux race detector",
		"name: Windows compatibility",
		"name: macOS compatibility",
		"GOOS=darwin GOARCH=amd64",
		"GOOS=darwin GOARCH=arm64",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("CI workflow is missing supported-platform contract %q", required)
		}
	}
	if count := strings.Count(text, "timeout-minutes:"); count != 5 {
		t.Fatalf("CI timeout count = %d, expected one for each of 5 jobs", count)
	}
}

func TestCIFuzzSmokeKeepsReviewedBoundaries(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, target := range []string{
		"FuzzParseBearerCredentialsJSON",
		"FuzzParseRepositorySet",
		"FuzzDecodeOPAResponse",
		"FuzzParseWorkflow",
		"FuzzParseManifest",
		"FuzzParseConfiguration",
		"FuzzParseAgentMarkdown",
		"FuzzParseAgenticWorkflow",
		"FuzzRequestPage",
		"FuzzRequestBoundedQueryValue",
		"FuzzRejectUnknownQueryParameters",
		"FuzzValidateEvent",
	} {
		invocation := "-fuzz=^" + target + "$ -fuzztime=10s -parallel=4"
		if !strings.Contains(text, invocation) {
			t.Fatalf("CI fuzz smoke is missing reviewed invocation %q", invocation)
		}
	}
	if count := strings.Count(text, "-fuzztime=10s -parallel=4"); count != 12 {
		t.Fatalf("CI fuzz target count = %d, expected 12", count)
	}
}

func TestLicenseScannerVersionPolicyAndEntryPointsStayAligned(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "scripts", "verify-licenses.sh"),
		filepath.Join(root, "scripts", "verify-licenses.cmd"),
	}
	var expectedVersion string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		version := semanticVersion.FindString(string(content))
		if version == "" {
			t.Fatalf("%s does not pin a scanner version", path)
		}
		if expectedVersion == "" {
			expectedVersion = version
		} else if version != expectedVersion {
			t.Fatalf("license scanner version = %s in %s, expected %s", version, path, expectedVersion)
		}
	}

	policy, err := os.ReadFile(filepath.Join(root, "config", "allowed-go-licenses.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(policy)) != "Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT" {
		t.Fatalf("unexpected Go license allowlist %q", strings.TrimSpace(string(policy)))
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "license-scan.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	if !strings.Contains(text, "bash ./scripts/verify-licenses.sh license-report.csv") || !strings.Contains(text, "if-no-files-found: error") {
		t.Fatal("license workflow does not enforce the reviewed scanner and report contract")
	}
}

func TestContainerScannerAndBaseImagesStayPinned(t *testing.T) {
	root := filepath.Join("..", "..")
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "container-security.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		`GRYPE_VERSION: "0.119.0"`,
		`GRYPE_LINUX_AMD64_SHA256: "3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b"`,
		"sha256sum --check --strict",
		"grype docker:opscustodian:security-scan --fail-on high --output table",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("container security workflow is missing reviewed contract %q", required)
		}
	}
	if strings.Contains(text, "only-fixed") || strings.Contains(text, "continue-on-error") {
		t.Fatal("container security workflow weakens the blocking vulnerability gate")
	}
}

func TestVulnerabilityScannerVersionAndEntryPointsStayAligned(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "scripts", "verify-vulnerabilities.sh"),
		filepath.Join(root, "scripts", "verify-vulnerabilities.cmd"),
	}
	var expectedVersion string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		version := semanticVersion.FindString(string(content))
		if version == "" {
			t.Fatalf("%s does not pin a scanner version", path)
		}
		if expectedVersion == "" {
			expectedVersion = version
		} else if version != expectedVersion {
			t.Fatalf("scanner version = %s in %s, expected %s", version, path, expectedVersion)
		}
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "vulnerability-scan.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "bash ./scripts/verify-vulnerabilities.sh") {
		t.Fatal("vulnerability workflow does not invoke the reviewed scanner entry point")
	}
}

func collectWorkflowActions(value any, actions *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "uses" {
				if action, ok := child.(string); ok {
					*actions = append(*actions, action)
				}
				continue
			}
			collectWorkflowActions(child, actions)
		}
	case []any:
		for _, child := range typed {
			collectWorkflowActions(child, actions)
		}
	}
}
