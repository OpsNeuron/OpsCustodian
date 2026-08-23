package contracts_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestKubernetesDeploymentContractIsRestrictedAndSecretReferenceOnly(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "kubernetes")
	base := filepath.Join(root, "base")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 {
		t.Fatalf("base manifest count = %d, expected 8", len(entries))
	}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		if document["apiVersion"] == nil || document["kind"] == nil {
			t.Fatalf("manifest %s lacks apiVersion or kind", entry.Name())
		}
	}

	deployment, err := os.ReadFile(filepath.Join(base, "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(deployment)
	for _, required := range []string{
		"replicas: 1", "automountServiceAccountToken: false", "runAsNonRoot: true", "runAsUser: 65532",
		"allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true", "drop: [ALL]",
		"http://127.0.0.1:8080/readyz", "ghcr.io/opsneuron/opscustodian:REPLACE_VERSION",
		"secretKeyRef: { name: opscustodian-secrets, key: database-dsn }",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("deployment lacks required contract %q", required)
		}
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork: true", "hostPath:", ":latest", "value: postgres://", "value: REPLACE_HIGH_ENTROPY_API_TOKEN"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("deployment contains forbidden contract %q", forbidden)
		}
	}

	kustomization, err := os.ReadFile(filepath.Join(base, "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(kustomization), "secret.example.yaml") {
		t.Fatal("example Secret must not be applied by the base kustomization")
	}
	secretExample, err := os.ReadFile(filepath.Join(root, "secret.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(secretExample, []byte("database-dsn: postgres")) || bytes.Contains(secretExample, []byte("api-token: opscustodian")) {
		t.Fatal("example Secret contains a credential-like literal")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(secretExample))
	count := 0
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("example Secret document count = %d", count)
	}
}
