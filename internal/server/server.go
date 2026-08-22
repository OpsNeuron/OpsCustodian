package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/store"
	"github.com/opscustodian/opscustodian/internal/validation"
)

const maximumSnapshotRequestBytes int64 = 10 << 20

type API struct {
	reader       store.Reader
	writer       store.Writer
	buildVersion string
}

type listResponse[T any] struct {
	APIVersion string `json:"apiVersion"`
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type valueResponse[T any] struct {
	APIVersion string `json:"apiVersion"`
	Value      T      `json:"value"`
}

type snapshotIngestionResponse struct {
	RepositoryID string `json:"repositoryId"`
	SnapshotID   string `json:"snapshotId"`
	Revision     string `json:"revision"`
	GeneratedAt  string `json:"generatedAt,omitempty"`
	AssetCount   int    `json:"assetCount"`
	FindingCount int    `json:"findingCount"`
}

type errorResponse struct {
	APIVersion string `json:"apiVersion"`
	Error      struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewHandler(reader store.Reader, buildVersion string) http.Handler {
	return newHandler(reader, buildVersion, nil, nil)
}

func NewAuthenticatedHandler(reader store.Reader, buildVersion string, authenticator BearerAuthenticator) http.Handler {
	return newHandler(reader, buildVersion, &authenticator, nil)
}

func newHandler(reader store.Reader, buildVersion string, authenticator *BearerAuthenticator, authorizer *ScopeAuthorizer) http.Handler {
	writer, _ := reader.(store.Writer)
	api := &API{reader: reader, writer: writer, buildVersion: buildVersion}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /api/v1/contracts", api.contracts)
	mux.HandleFunc("GET /api/v1/repositories", api.repositories)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/bom", api.latestBOM)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/snapshots", api.snapshots)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/snapshots/{snapshotID}/bom", api.snapshotBOM)
	mux.HandleFunc("GET /api/v1/findings", api.findings)
	mux.HandleFunc("GET /api/v1/finding-lifecycles", api.findingLifecycles)
	mux.HandleFunc("POST /api/v1/snapshots", api.ingestSnapshot)
	var handler http.Handler = mux
	if authorizer != nil {
		handler = authorizer.middleware(handler)
	}
	if authenticator != nil {
		handler = authenticator.middleware(handler)
	}
	return securityHeaders(handler)
}

func (api *API) ingestSnapshot(w http.ResponseWriter, request *http.Request) {
	if api.writer == nil {
		writeError(w, http.StatusServiceUnavailable, "snapshot-writer-unavailable", "snapshot ingestion is unavailable")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content-type-required", "Content-Type must be application/json")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, maximumSnapshotRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var bom model.AgentBOM
	if err := decoder.Decode(&bom); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "snapshot-too-large", fmt.Sprintf("Agent BOM must not exceed %d bytes", maximumSnapshotRequestBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid-json", "request body must contain one valid Agent BOM JSON document")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid-json", "request body must contain one valid Agent BOM JSON document")
		return
	}
	if issues := validation.Validate(bom); len(issues) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid-agent-bom", "Agent BOM does not satisfy the supported contract")
		return
	}
	snapshot, err := api.writer.PutSnapshot(request.Context(), bom)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "immutable-snapshot-conflict", "the repository revision already exists with different content")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-write-failed", "snapshot could not be persisted")
		return
	}
	writeJSON(w, http.StatusCreated, valueResponse[snapshotIngestionResponse]{APIVersion: contracts.ControlPlaneAPIVersion, Value: snapshotIngestionResponse{
		SnapshotID: snapshot.SnapshotID, RepositoryID: snapshot.RepositoryID, Revision: snapshot.BOM.Metadata.Revision,
		GeneratedAt: snapshot.BOM.Metadata.GeneratedAt, AssetCount: len(snapshot.BOM.Assets), FindingCount: len(snapshot.BOM.Findings),
	}})
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func (api *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *API) contracts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, valueResponse[contracts.Info]{APIVersion: contracts.ControlPlaneAPIVersion, Value: contracts.BuildInfo(api.buildVersion)})
}

func (api *API) repositories(w http.ResponseWriter, request *http.Request) {
	page, ok := requestPage(w, request, "repositories")
	if !ok {
		return
	}
	result, err := api.reader.ListRepositories(request.Context(), page)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository inventory is unavailable")
		return
	}
	if result.Items == nil {
		result.Items = []store.RepositorySummary{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.RepositorySummary]{APIVersion: contracts.ControlPlaneAPIVersion, Items: result.Items, NextCursor: encodeCursor("repositories", result.NextCursor)})
}

func (api *API) snapshots(w http.ResponseWriter, request *http.Request) {
	repositoryID := request.PathValue("repositoryID")
	if !validRepositoryID(repositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	page, ok := requestPage(w, request, "snapshots:"+repositoryID)
	if !ok {
		return
	}
	result, err := api.reader.ListSnapshots(request.Context(), repositoryID, page)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "repository-not-found", "repository was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "snapshot history is unavailable")
		return
	}
	if result.Items == nil {
		result.Items = []store.SnapshotSummary{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.SnapshotSummary]{APIVersion: contracts.ControlPlaneAPIVersion, Items: result.Items, NextCursor: encodeCursor("snapshots:"+repositoryID, result.NextCursor)})
}

func (api *API) snapshotBOM(w http.ResponseWriter, request *http.Request) {
	repositoryID, snapshotID := request.PathValue("repositoryID"), request.PathValue("snapshotID")
	if !validRepositoryID(repositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if !validSnapshotID(snapshotID) {
		writeError(w, http.StatusBadRequest, "invalid-snapshot-id", "snapshot ID is invalid")
		return
	}
	snapshot, err := api.reader.Snapshot(request.Context(), repositoryID, snapshotID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "snapshot-not-found", "snapshot was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository snapshot is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, valueResponse[store.Snapshot]{APIVersion: contracts.ControlPlaneAPIVersion, Value: snapshot})
}

func (api *API) latestBOM(w http.ResponseWriter, request *http.Request) {
	id := request.PathValue("repositoryID")
	if !validRepositoryID(id) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	snapshot, err := api.reader.LatestSnapshot(request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "repository-not-found", "repository was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository snapshot is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, valueResponse[store.Snapshot]{APIVersion: contracts.ControlPlaneAPIVersion, Value: snapshot})
}

func (api *API) findings(w http.ResponseWriter, request *http.Request) {
	filter := store.FindingFilter{RepositoryID: request.URL.Query().Get("repositoryId"), Severity: strings.ToLower(request.URL.Query().Get("severity"))}
	if filter.RepositoryID != "" && !validRepositoryID(filter.RepositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if filter.Severity != "" && !validSeverity(filter.Severity) {
		writeError(w, http.StatusBadRequest, "invalid-severity", "severity must be info, low, medium, high, or critical")
		return
	}
	scope := "findings:" + filter.RepositoryID + ":" + filter.Severity
	page, ok := requestPage(w, request, scope)
	if !ok {
		return
	}
	filter.Page = page
	result, err := api.reader.ListFindings(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "finding inventory is unavailable")
		return
	}
	if result.Items == nil {
		result.Items = []store.FindingRecord{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.FindingRecord]{APIVersion: contracts.ControlPlaneAPIVersion, Items: result.Items, NextCursor: encodeCursor(scope, result.NextCursor)})
}

func (api *API) findingLifecycles(w http.ResponseWriter, request *http.Request) {
	filter := store.FindingLifecycleFilter{
		RepositoryID: request.URL.Query().Get("repositoryId"),
		Severity:     strings.ToLower(request.URL.Query().Get("severity")),
		Status:       strings.ToLower(request.URL.Query().Get("status")),
	}
	if filter.RepositoryID != "" && !validRepositoryID(filter.RepositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if filter.Severity != "" && !validSeverity(filter.Severity) {
		writeError(w, http.StatusBadRequest, "invalid-severity", "severity must be info, low, medium, high, or critical")
		return
	}
	if filter.Status != "" && !validLifecycleStatus(filter.Status) {
		writeError(w, http.StatusBadRequest, "invalid-lifecycle-status", "status must be introduced, persisting, or resolved")
		return
	}
	scope := "finding-lifecycles:" + filter.RepositoryID + ":" + filter.Severity + ":" + filter.Status
	page, ok := requestPage(w, request, scope)
	if !ok {
		return
	}
	filter.Page = page
	result, err := api.reader.ListFindingLifecycle(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "finding lifecycle is unavailable")
		return
	}
	if result.Items == nil {
		result.Items = []store.FindingLifecycleRecord{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.FindingLifecycleRecord]{APIVersion: contracts.ControlPlaneAPIVersion, Items: result.Items, NextCursor: encodeCursor(scope, result.NextCursor)})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, request)
	})
}

func validRepositoryID(value string) bool {
	return validOpaqueID(value, "repository-")
}

func validSnapshotID(value string) bool {
	return validOpaqueID(value, "snapshot-")
}

func validOpaqueID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+16 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func requestPage(w http.ResponseWriter, request *http.Request, scope string) (store.PageRequest, bool) {
	page := store.PageRequest{Limit: 50}
	if raw := request.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, http.StatusBadRequest, "invalid-limit", "limit must be an integer between 1 and 200")
			return store.PageRequest{}, false
		}
		page.Limit = limit
	}
	if raw := request.URL.Query().Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		prefix := "v1\x00" + scope + "\x00"
		if err != nil || len(decoded) > 512 || !strings.HasPrefix(string(decoded), prefix) {
			writeError(w, http.StatusBadRequest, "invalid-cursor", "cursor is invalid or unsupported")
			return store.PageRequest{}, false
		}
		page.Cursor = strings.TrimPrefix(string(decoded), prefix)
	}
	return page, true
}

func encodeCursor(scope, value string) string {
	if value == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte("v1\x00" + scope + "\x00" + value))
}

func validSeverity(value string) bool {
	return value == "info" || value == "low" || value == "medium" || value == "high" || value == "critical"
}

func validLifecycleStatus(value string) bool {
	return value == "introduced" || value == "persisting" || value == "resolved"
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	response := errorResponse{APIVersion: contracts.ControlPlaneAPIVersion}
	response.Error.Code, response.Error.Message = code, message
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
