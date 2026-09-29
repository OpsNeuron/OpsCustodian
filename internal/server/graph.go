package server

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

type graphFilter struct {
	RepositoryID     string
	AssetType        string
	Owner            string
	Component        string
	Action           string
	RelationshipType string
}

func requestGraphFilter(w http.ResponseWriter, request *http.Request) (graphFilter, bool) {
	values := make(map[string]string, 6)
	for _, name := range []string{"repositoryId", "assetType", "owner", "component", "action", "relationshipType"} {
		code := "invalid-graph-filter"
		message := name + " must be a single trimmed value of at most 200 bytes"
		if name == "repositoryId" {
			code = "invalid-repository-id"
		}
		value, ok := requestBoundedQueryValue(w, request, name, code, message)
		if !ok {
			return graphFilter{}, false
		}
		values[name] = value
	}
	filter := graphFilter{
		RepositoryID: values["repositoryId"], AssetType: values["assetType"], Owner: values["owner"],
		Component: values["component"], Action: values["action"], RelationshipType: values["relationshipType"],
	}
	if filter.RepositoryID != "" && !validRepositoryID(filter.RepositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return graphFilter{}, false
	}
	return filter, true
}

func (filter graphFilter) cursorScope() string {
	return boundedCursorScope("graph", filter.RepositoryID, filter.AssetType, filter.Owner, filter.Component, filter.Action, filter.RelationshipType)
}

func boundedCursorScope(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return fmt.Sprintf("%s:%x", prefix, sum[:8])
}

func (filter graphFilter) matches(bom model.AgentBOM) bool {
	if filter.AssetType != "" || filter.Owner != "" || filter.Component != "" {
		matched := false
		for _, asset := range bom.Assets {
			if filter.AssetType != "" && asset.Type != filter.AssetType {
				continue
			}
			if filter.Component != "" && asset.Component != filter.Component {
				continue
			}
			if filter.Owner != "" && !assetOwnedBy(asset, filter.Owner) {
				continue
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	if filter.Action != "" {
		matched := false
		for _, asset := range bom.Assets {
			for _, capability := range asset.Capabilities {
				matched = matched || capability.Action == filter.Action
			}
		}
		for _, path := range bom.AccessPaths {
			matched = matched || path.Capability.Action == filter.Action
		}
		if !matched {
			return false
		}
	}
	if filter.RelationshipType != "" {
		for _, relationship := range bom.Relationships {
			if relationship.Type == filter.RelationshipType {
				return true
			}
		}
		return false
	}
	return true
}

func assetOwnedBy(asset model.Asset, owner string) bool {
	if asset.LegacyOwner == owner {
		return true
	}
	for _, candidate := range asset.Owners {
		if candidate == owner {
			return true
		}
	}
	return false
}
