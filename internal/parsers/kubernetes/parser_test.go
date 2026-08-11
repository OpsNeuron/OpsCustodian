package kubernetes

import (
	"context"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

func TestParseWorkloadTokenProjectionAndStableEvidence(t *testing.T) {
	artifact := kubernetesArtifact(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent
  namespace: production
automountServiceAccountToken: false
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
      automountServiceAccountToken: true
      containers:
        - name: agent
          image: example.invalid/agent:v1
          volumeMounts:
            - name: api-token
              mountPath: /var/run/secrets/agent
      volumes:
        - name: api-token
          projected:
            sources:
              - serviceAccountToken:
                  audience: automation-api
                  expirationSeconds: 7200
                  path: token
`)

	first := parseAssets(t, artifact)
	second := parseAssets(t, artifact)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected two assets, got %d and %d", len(first), len(second))
	}
	for index := range first {
		if first[index].ID != second[index].ID || first[index].Evidence[0].ID != second[index].Evidence[0].ID {
			t.Fatalf("parse is not stable at asset %d", index)
		}
	}

	serviceAccount := parserAssetByID(t, first, "kubernetes:service-account:production/agent")
	assertParserBooleanControl(t, serviceAccount, "automountServiceAccountToken", false)
	workload := parserAssetByID(t, first, "kubernetes:workload:production/deployment/remediator")
	assertParserBooleanControl(t, workload, "automountServiceAccountToken", true)
	if len(workload.Identities) != 1 || workload.Identities[0].Reference != "production/agent" {
		t.Fatalf("unexpected workload identity %#v", workload.Identities)
	}
	projection := parserControlByType(t, workload.Controls, "serviceAccountTokenProjection")
	value := projection.Value.(map[string]any)
	if value["audience"] != "automation-api" || value["expirationSeconds"] != 7200 || value["path"] != "token" {
		t.Fatalf("unexpected projection %#v", value)
	}
	mountedBy := value["mountedBy"].([]string)
	if len(mountedBy) != 1 || mountedBy[0] != "agent" {
		t.Fatalf("unexpected projection consumers %#v", mountedBy)
	}
	assertParserCapability(t, workload, "kubernetes.service_account_token.project", "kubernetes:token-audience/automation-api")
}

func TestParseRBACResourceNamesNonResourceURLsAndAggregation(t *testing.T) {
	assets := parseAssets(t, kubernetesArtifact(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: source-reader
  labels:
    opscustodian.dev/tier: reader
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    resourceNames: ["nightly-cleanup"]
    verbs: ["get", "patch"]
  - nonResourceURLs: ["/healthz", "/metrics"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aggregate-reader
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        opscustodian.dev/tier: reader
    - matchExpressions:
        - key: opscustodian.dev/tier
          operator: In
          values: ["reader", "observer"]
rules: []
`))

	source := parserAssetByID(t, assets, "kubernetes:role:cluster/source-reader")
	labels := parserControlByType(t, source.Controls, "kubernetesLabels").Value.(map[string]string)
	if labels["opscustodian.dev/tier"] != "reader" {
		t.Fatalf("unexpected labels %#v", labels)
	}
	assertParserCapability(t, source, "kubernetes.jobs.get", "kubernetes:cluster/source-reader/batch/jobs/nightly-cleanup")
	assertParserCapability(t, source, "kubernetes.jobs.patch", "kubernetes:cluster/source-reader/batch/jobs/nightly-cleanup")
	assertParserCapability(t, source, "kubernetes.non_resource_url.get", "kubernetes:cluster/non-resource-url/healthz")
	assertParserCapability(t, source, "kubernetes.non_resource_url.get", "kubernetes:cluster/non-resource-url/metrics")
	if len(source.Capabilities) != 4 {
		t.Fatalf("expected four exact capabilities without phantom wildcards, got %#v", source.Capabilities)
	}

	aggregate := parserAssetByID(t, assets, "kubernetes:role:cluster/aggregate-reader")
	selectors := parserControlByType(t, aggregate.Controls, "kubernetesAggregationRule").Value.([]map[string]any)
	if len(selectors) != 2 {
		t.Fatalf("expected two aggregation selectors, got %#v", selectors)
	}
	matchLabels := selectors[0]["matchLabels"].(map[string]string)
	if matchLabels["opscustodian.dev/tier"] != "reader" {
		t.Fatalf("unexpected matchLabels %#v", matchLabels)
	}
	expressions := selectors[1]["matchExpressions"].([]map[string]any)
	if len(expressions) != 1 || expressions[0]["operator"] != "In" {
		t.Fatalf("unexpected matchExpressions %#v", expressions)
	}
}

func TestParseReportsMalformedDocumentIndex(t *testing.T) {
	artifact := kubernetesArtifact(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: valid
---
apiVersion: apps/v1
kind: Deployment
metadata: [broken
`)
	_, err := (Parser{}).Parse(context.Background(), artifact)
	if err == nil || !strings.Contains(err.Error(), "document 2") {
		t.Fatalf("expected document-indexed parse error, got %v", err)
	}
}

func kubernetesArtifact(content string) discovery.Artifact {
	return discovery.Artifact{Path: "C:/repo/k8s/runtime.yaml", RelPath: "k8s/runtime.yaml", Content: []byte(content)}
}

func parseAssets(t *testing.T, artifact discovery.Artifact) []model.Asset {
	t.Helper()
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("parse Kubernetes fixture: %v", err)
	}
	return assets
}

func parserAssetByID(t *testing.T, assets []model.Asset, id string) *model.Asset {
	t.Helper()
	for index := range assets {
		if assets[index].ID == id {
			return &assets[index]
		}
	}
	t.Fatalf("asset %s not found in %#v", id, assets)
	return nil
}

func parserControlByType(t *testing.T, controls []model.Control, controlType string) model.Control {
	t.Helper()
	for _, control := range controls {
		if control.Type == controlType {
			return control
		}
	}
	t.Fatalf("control %s not found in %#v", controlType, controls)
	return model.Control{}
}

func assertParserBooleanControl(t *testing.T, asset *model.Asset, controlType string, expected bool) {
	t.Helper()
	control := parserControlByType(t, asset.Controls, controlType)
	if value, ok := control.Value.(bool); !ok || value != expected {
		t.Fatalf("control %s = %#v, expected %t", controlType, control.Value, expected)
	}
}

func assertParserCapability(t *testing.T, asset *model.Asset, action, resource string) {
	t.Helper()
	for _, capability := range asset.Capabilities {
		if capability.Action == action && capability.Resource == resource {
			return
		}
	}
	t.Fatalf("capability %s on %s not found in %#v", action, resource, asset.Capabilities)
}
