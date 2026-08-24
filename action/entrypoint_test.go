package action

import (
	"os"
	"strings"
	"testing"
)

func TestDockerEntrypointReadsGitHubHyphenatedInputNames(t *testing.T) {
	content, err := os.ReadFile("entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	for _, input := range []string{"BASELINE-BOM", "PROPOSED-BOM", "SCAN-PATH", "FAIL-ON", "SARIF-OUTPUT", "MAX-FILE-SIZE"} {
		if !strings.Contains(script, `action_input "`+input+`"`) {
			t.Fatalf("entrypoint does not read GitHub Docker action input %s", input)
		}
	}
	if strings.Contains(script, "eval ") {
		t.Fatal("entrypoint must not use eval to resolve action inputs")
	}
}

func TestExampleWorkflowGrantsSARIFUploaderReadAccess(t *testing.T) {
	content, err := os.ReadFile("../examples/github-actions/opscustodian.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(content)
	for _, expected := range []string{"actions: read", "contents: read", "security-events: write", "github/codeql-action/upload-sarif@v4"} {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("example workflow is missing %q", expected)
		}
	}
}
