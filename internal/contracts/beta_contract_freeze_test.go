package contracts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/contracts"
)

func TestBetaContractFreezeMatchesExecutableRegistry(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "BETA_CONTRACT_FREEZE.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	info := contracts.BuildInfo("test")
	required := []string{
		info.Contracts.AgentBOM,
		info.Contracts.Normalization,
		info.Contracts.Findings,
		info.Contracts.PolicyInput,
		info.Contracts.PolicyDecision,
		info.Contracts.AuditEvent,
		info.Contracts.ControlPlane,
		info.Contracts.RepositorySet,
		info.Contracts.Preflight,
		info.Contracts.SARIF,
		"migrations 1 through 4",
		"no known imminent redesign",
		"Golden files have no automatic update switch",
	}
	for _, value := range required {
		if value == "" || !strings.Contains(text, value) {
			t.Fatalf("beta contract freeze is missing registry boundary %q", value)
		}
	}
}
