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
	filter := graphFilter{
		RepositoryID: request.URL.Query().Get("repositoryId"), AssetType: request.URL.Query().Get("assetType"),
		Owner: request.URL.Query().Get("owner"), Component: request.URL.Query().Get("component"),
		Action: request.URL.Query().Get("action"), RelationshipType: request.URL.Query().Get("relationshipType"),
	}
	for name, value := range map[string]string{
		"assetType": filter.AssetType, "owner": filter.Owner, "component": filter.Component,
		"action": filter.Action, "relationshipType": filter.RelationshipType,
	} {
		if value != strings.TrimSpace(value) || len(value) > 200 || strings.ContainsAny(value, "\x00\r\n") {
			writeError(w, http.StatusBadRequest, "invalid-graph-filter", fmt.Sprintf("%s must be a trimmed value of at most 200 bytes", name))
			return graphFilter{}, false
		}
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
