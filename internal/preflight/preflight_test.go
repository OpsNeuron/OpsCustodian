package preflight

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluatePolicyProfileIsDeterministicAndSecretFree(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "policies")
	if err := os.Mkdir(policy, 0o700); err != nil {
		t.Fatal(err)
	}
	report := Evaluate(Options{Profile: "policy", OPAPath: "opa", PolicyPath: policy, LookPath: func(string) (string, error) { return "/safe/opa", nil }})
	if !report.Ready || len(report.Checks) != 2 || report.Checks[0].ID != "opa-binary" || report.Checks[1].ID != "policy-bundle" {
		t.Fatalf("report = %#v", report)
	}
	var output bytes.Buffer
	if err := Write(&output, report, "json"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "/safe/opa") || strings.Contains(output.String(), policy) {
		t.Fatalf("report leaked paths: %s", output.String())
	}
}

func TestEvaluateReleaseProfileFailsClosedWithBoundedCheckIDs(t *testing.T) {
	report := Evaluate(Options{
		Profile: "release", Root: t.TempDir(), OPAPath: "opa", PolicyPath: "missing",
		LookupEnv: func(string) (string, bool) { return "secret-value", true },
		LookPath:  func(string) (string, error) { return "", errors.New("secret backend detail") },
	})
	if report.Ready || len(report.Checks) != 6 {
		t.Fatalf("report = %#v", report)
	}
	var output bytes.Buffer
	if err := Write(&output, report, "terminal"); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-value", "secret backend detail", "missing"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("report leaked %q: %s", forbidden, output.String())
		}
	}
}

func TestEvaluateServerProfileDetectsMissingGitHubAppConfiguration(t *testing.T) {
	root := t.TempDir()
	repositorySetPath := filepath.Join(root, "repositories.json")
	content := `{"apiVersion":"opscustodian.dev/ingestion/v1alpha1","kind":"RepositorySet","schedule":{"interval":"1m","maxConcurrency":1,"retry":{"maxAttempts":1}},"repositories":[{"source":"github:acme/platform","connector":"github","ref":"main","credentialReference":"github-app:installation:42"}]}`
	if err := os.WriteFile(repositorySetPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://database/controlplane", "OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN": "doctor-test-token-0123456789abcdefghijkl", "OPSCUSTODIAN_API_TOKEN_ID": "doctor",
		"OPSCUSTODIAN_API_SCOPES": "control-plane:read", "OPSCUSTODIAN_REPOSITORY_SET_FILE": repositorySetPath,
	}
	report := Evaluate(Options{Profile: "server", LookupEnv: func(name string) (string, bool) { value, ok := values[name]; return value, ok }})
	if report.Ready || len(report.Checks) != 3 || report.Checks[2].ID != "github-app-key" || report.Checks[2].Status != StatusFailed || !report.Checks[2].Required {
		t.Fatalf("report = %#v", report)
	}
}

func TestEvaluateBetaProfileRequiresReleaseEvidenceFiles(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"LICENSE",
		filepath.Join("docs", "INTEGRATION_TESTING.md"),
		filepath.Join("docs", "RELEASE.md"),
		filepath.Join(".github", "workflows", "fuzz-extended.yml"),
		filepath.Join(".github", "workflows", "codeql.yml"),
	} {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := Evaluate(Options{
		Profile: "beta", Root: root, OPAPath: "opa", PolicyPath: root,
		LookupEnv: func(name string) (string, bool) {
			values := map[string]string{
				"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
				"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
				"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
				"OPSCUSTODIAN_API_TOKEN":               "doctor-test-token-0123456789abcdefghijkl",
				"OPSCUSTODIAN_API_TOKEN_ID":            "doctor",
				"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
			}
			value, ok := values[name]
			return value, ok
		},
		LookPath: func(string) (string, error) { return "/safe/opa", nil },
	})
	if !report.Ready || len(report.Checks) != 10 {
		t.Fatalf("report = %#v", report)
	}
	for _, check := range report.Checks {
		if check.Required && check.Status != StatusPassed {
			t.Fatalf("required beta check failed: %#v", check)
		}
	}
}
