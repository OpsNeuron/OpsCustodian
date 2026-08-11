package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/parsers"
	"github.com/opscustodian/opscustodian/internal/parsers/kubernetes"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func TestScanKubernetesRepositoryEndToEnd(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "CODEOWNERS"), "/k8s/** @platform-team\n")
	writeFixture(t, filepath.Join(root, "k8s", "runtime.yaml"), scannerKubernetesFixture)
	opts := Options{
		Root: root, Source: "fixture-repository", Revision: "test", Generator: "scanner-test",
		Parsers: []parsers.Parser{kubernetes.Parser{}}, Boundaries: []string{"k8s=runtime-platform"},
	}

	first, err := Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if issues := validation.Validate(first); len(issues) != 0 {
		t.Fatalf("generated BOM is invalid: %#v", issues)
	}
	if len(first.Assets) != 4 {
		t.Fatalf("expected four Kubernetes assets, got %d", len(first.Assets))
	}
	if len(first.AccessPaths) != 2 {
		t.Fatalf("expected identity and workload access paths, got %d", len(first.AccessPaths))
	}
	if len(first.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", first.Diagnostics)
	}
	for _, asset := range first.Assets {
		if asset.Component != "runtime-platform" {
			t.Errorf("asset %s component = %q", asset.ID, asset.Component)
		}
		if !reflect.DeepEqual(asset.Owners, []string{"@platform-team"}) {
			t.Errorf("asset %s owners = %#v", asset.ID, asset.Owners)
		}
	}
	workload := scannerAssetByID(t, first.Assets, "kubernetes:workload:production/deployment/remediator")
	assertScannerCapability(t, workload, "kubernetes.pods.get", "kubernetes:production/core/pods/*")
	assertScannerCapability(t, workload, "kubernetes.service_account_token.use", "kubernetes:service-account/production/agent")
	assertScannerControl(t, workload.Controls, "declaredVsEffectiveAccess")
	for _, relationType := range []string{"runs-as", "binds-subject", "grants-role", "owned-by"} {
		if !hasRelationshipType(first.Relationships, relationType) {
			t.Errorf("relationship type %s not found", relationType)
		}
	}

	second, err := Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	first.Metadata.GeneratedAt, second.Metadata.GeneratedAt = "", ""
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated scans differ after removing generatedAt")
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func scannerAssetByID(t *testing.T, assets []model.Asset, id string) *model.Asset {
	t.Helper()
	for index := range assets {
		if assets[index].ID == id {
			return &assets[index]
		}
	}
	t.Fatalf("asset %s not found", id)
	return nil
}

func assertScannerCapability(t *testing.T, asset *model.Asset, action, resource string) {
	t.Helper()
	for _, capability := range asset.Capabilities {
		if capability.Action == action && capability.Resource == resource {
			return
		}
	}
	t.Errorf("capability %s on %s not found in %#v", action, resource, asset.Capabilities)
}

func assertScannerControl(t *testing.T, controls []model.Control, controlType string) {
	t.Helper()
	for _, control := range controls {
		if control.Type == controlType {
			return
		}
	}
	t.Errorf("control %s not found in %#v", controlType, controls)
}

func hasRelationshipType(relationships []model.Relationship, relationType string) bool {
	for _, relationship := range relationships {
		if relationship.Type == relationType {
			return true
		}
	}
	return false
}

const scannerKubernetesFixture = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent
  namespace: production
automountServiceAccountToken: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: remediator
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: agent
      containers:
        - name: agent
          image: example.invalid/agent:v1
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader
  namespace: production
subjects:
  - kind: ServiceAccount
    name: agent
    namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
`
