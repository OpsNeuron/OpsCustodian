package correlation

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

func Build(bom *model.AgentBOM) {
	assetsByKindAndName := map[string]string{}
	for _, asset := range bom.Assets {
		assetsByKindAndName[lookupKey(asset.Type, asset.Name)] = asset.ID
	}
	relations := map[string]model.Relationship{}
	for _, asset := range bom.Assets {
		evidenceIDs, confidence := relationshipEvidence(asset)
		for _, owner := range asset.Owners {
			if owner != "" {
				ownerEvidenceIDs, ownerConfidence := ownershipEvidence(asset, evidenceIDs, confidence)
				add(relations, relationship(asset.ID, "owned-by", "owner:"+owner, "owner", ownerConfidence, ownerEvidenceIDs))
			}
		}
		for _, tool := range asset.Tools {
			target := "tool:" + tool.Type + ":" + tool.Reference
			targetType := "tool"
			relationType := "uses-tool"
			if tool.Type == "mcp-server" {
				relationType = "uses-mcp-server"
				if assetID, exists := assetsByKindAndName[lookupKey("mcp-server", tool.Reference)]; exists {
					target, targetType = assetID, "asset"
				} else {
					target, targetType = "mcp-server:"+tool.Reference, "asset-reference"
				}
			}
			add(relations, relationship(asset.ID, relationType, target, targetType, confidence, evidenceIDs))
		}
		for _, credential := range asset.Credentials {
			target := "credential:" + credential.Type + ":" + credential.Reference
			add(relations, relationship(asset.ID, "uses-credential", target, "credential", confidence, evidenceIDs))
		}
		for _, identity := range asset.Identities {
			target := "identity:" + identity.Reference
			targetType := "asset-reference"
			if assetID, exists := assetsByKindAndName[lookupKey("identity", identity.Reference)]; exists {
				target, targetType = assetID, "asset"
			}
			relationType := "runs-as"
			if asset.Type == "authorization-binding" {
				relationType = "binds-subject"
			}
			add(relations, relationship(asset.ID, relationType, target, targetType, confidence, evidenceIDs))
		}
		for _, dependency := range asset.Dependencies {
			target := dependency.Type + ":" + dependency.Reference
			targetType := "asset-reference"
			if assetID, exists := assetsByKindAndName[lookupKey(dependency.Type, dependency.Reference)]; exists {
				target, targetType = assetID, "asset"
			}
			relationType := "depends-on"
			if asset.Type == "authorization-binding" && dependency.Type == "authorization-role" {
				relationType = "grants-role"
			}
			add(relations, relationship(asset.ID, relationType, target, targetType, confidence, evidenceIDs))
		}
	}
	bom.Relationships = make([]model.Relationship, 0, len(relations))
	for _, relation := range relations {
		bom.Relationships = append(bom.Relationships, relation)
	}
	sort.Slice(bom.Relationships, func(i, j int) bool { return bom.Relationships[i].ID < bom.Relationships[j].ID })
}

func relationship(from, relationType, to, targetType, confidence string, evidenceIDs []string) model.Relationship {
	value := from + "\x00" + relationType + "\x00" + to
	sum := sha256.Sum256([]byte(value))
	return model.Relationship{
		ID: fmt.Sprintf("relation-%x", sum[:6]), From: from, Type: relationType,
		To: to, TargetType: targetType, Confidence: confidence,
		EvidenceIDs: append([]string(nil), evidenceIDs...),
	}
}

func add(relations map[string]model.Relationship, relation model.Relationship) {
	relations[relation.ID] = relation
}

func lookupKey(kind, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
}

func relationshipEvidence(asset model.Asset) ([]string, string) {
	if len(asset.Evidence) == 0 {
		return nil, "low"
	}
	confidence := asset.Evidence[0].Confidence
	if confidence == "" {
		confidence = "medium"
	}
	return []string{asset.Evidence[0].ID}, confidence
}

func ownershipEvidence(asset model.Asset, fallbackIDs []string, fallbackConfidence string) ([]string, string) {
	for _, evidence := range asset.Evidence {
		if evidence.Parser == "codeowners" || evidence.Parser == "backstage" {
			return []string{evidence.ID}, evidence.Confidence
		}
	}
	return fallbackIDs, fallbackConfidence
}
