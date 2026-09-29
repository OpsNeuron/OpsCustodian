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

	"github.com/opscustodian/opscustodian/internal/audit"
	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/normalize"
	"github.com/opscustodian/opscustodian/internal/store"
	"github.com/opscustodian/opscustodian/internal/validation"
)

const maximumSnapshotRequestBytes int64 = 10 << 20

type API struct {
	reader       store.Reader
	writer       store.Writer
	buildVersion string
	readiness    ReadinessReader
	policy       PolicyEvaluator
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

type organizationGraph struct {
	RepositoryID  string               `json:"repositoryId"`
	Source        string               `json:"source"`
	Revision      string               `json:"revision"`
	Assets        []model.Asset        `json:"assets"`
	Relationships []model.Relationship `json:"relationships"`
	AccessPaths   []model.AccessPath   `json:"accessPaths"`
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
	return newHandlerWithReadiness(reader, buildVersion, authenticator, authorizer, readyReadiness{})
}

func newHandlerWithReadiness(reader store.Reader, buildVersion string, authenticator *BearerAuthenticator, authorizer *ScopeAuthorizer, readiness ReadinessReader) http.Handler {
	return newHandlerWithReadinessAndPolicy(reader, buildVersion, authenticator, authorizer, readiness, nil)
}

func newHandlerWithReadinessAndPolicy(reader store.Reader, buildVersion string, authenticator *BearerAuthenticator, authorizer *ScopeAuthorizer, readiness ReadinessReader, evaluator PolicyEvaluator) http.Handler {
	writer, _ := reader.(store.Writer)
	if readiness == nil {
		readiness = (*ReadinessTracker)(nil)
	}
	api := &API{reader: reader, writer: writer, buildVersion: buildVersion, readiness: readiness, policy: evaluator}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.HandleFunc("GET /api/v1/contracts", api.contracts)
	mux.HandleFunc("GET /api/v1/repositories", api.repositories)
	mux.HandleFunc("GET /api/v1/graph", api.organizationGraph)
	mux.HandleFunc("GET /api/v1/audit-events", api.auditEvents)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/bom", api.latestBOM)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/snapshots", api.snapshots)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/snapshots/{snapshotID}/bom", api.snapshotBOM)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/drift", api.repositoryDrift)
	mux.HandleFunc("GET /api/v1/findings", api.findings)
	mux.HandleFunc("GET /api/v1/finding-lifecycles", api.findingLifecycles)
	mux.HandleFunc("POST /api/v1/snapshots", api.ingestSnapshot)
	mux.HandleFunc("POST /api/v1/policy/evaluate", api.evaluatePolicy)
	var handler http.Handler = mux
	if authorizer != nil {
		handler = authorizer.middleware(handler)
	}
	if authenticator != nil {
		handler = authenticator.middleware(handler)
	}
	return securityHeaders(handler)
}

func (api *API) ready(w http.ResponseWriter, _ *http.Request) {
	snapshot := api.readiness.Snapshot()
	status := http.StatusOK
	if snapshot.Status != ReadinessReady {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, snapshot)
}

func (api *API) ingestSnapshot(w http.ResponseWriter, request *http.Request) {
	setSnapshotIngestionAudit(request, audit.SnapshotIngestionObservation{Result: "rejected"})
	if api.writer == nil {
		setSnapshotIngestionAudit(request, audit.SnapshotIngestionObservation{Result: "unavailable"})
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
	repositoryID := store.RepositoryID(bom.Metadata.Source)
	if !authorizeRepository(w, request, repositoryID) {
		return
	}
	snapshot, err := api.writer.PutSnapshot(request.Context(), bom)
	if errors.Is(err, store.ErrConflict) {
		setSnapshotIngestionAudit(request, audit.SnapshotIngestionObservation{
			Result: "conflict", RepositoryID: repositoryID,
			SnapshotID: store.SnapshotID(repositoryID, bom.Metadata.Revision), Revision: bom.Metadata.Revision,
		})
		writeError(w, http.StatusConflict, "immutable-snapshot-conflict", "the repository revision already exists with different content")
		return
	}
	if err != nil {
		setSnapshotIngestionAudit(request, audit.SnapshotIngestionObservation{Result: "failed"})
		writeError(w, http.StatusInternalServerError, "store-write-failed", "snapshot could not be persisted")
		return
	}
	setSnapshotIngestionAudit(request, audit.SnapshotIngestionObservation{
		Result: "persisted", RepositoryID: snapshot.RepositoryID, SnapshotID: snapshot.SnapshotID,
		Revision: snapshot.BOM.Metadata.Revision, AssetCount: len(snapshot.BOM.Assets), FindingCount: len(snapshot.BOM.Findings),
	})
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
	if !rejectUnknownQueryParameters(w, request, "limit", "cursor") {
		return
	}
	page, ok := requestPage(w, request, "repositories")
	if !ok {
		return
	}
	page.RepositoryIDs = authorizedRepositoryIDs(request)
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

func (api *API) organizationGraph(w http.ResponseWriter, request *http.Request) {
	if !rejectUnknownQueryParameters(w, request, "repositoryId", "assetType", "owner", "component", "action", "relationshipType", "limit", "cursor") {
		return
	}
	filter, ok := requestGraphFilter(w, request)
	if !ok {
		return
	}
	if filter.RepositoryID != "" && !authorizeRepository(w, request, filter.RepositoryID) {
		return
	}
	page, ok := requestPage(w, request, filter.cursorScope())
	if !ok {
		return
	}
	if filter.RepositoryID != "" {
		page.RepositoryIDs = []string{filter.RepositoryID}
	} else {
		page.RepositoryIDs = authorizedRepositoryIDs(request)
	}
	repositories, err := api.reader.ListRepositories(request.Context(), page)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "organization graph is unavailable")
		return
	}
	items := make([]organizationGraph, 0, len(repositories.Items))
	for _, repository := range repositories.Items {
		snapshot, err := api.reader.LatestSnapshot(request.Context(), repository.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store-read-failed", "organization graph is unavailable")
			return
		}
		normalize.BOM(&snapshot.BOM)
		if !filter.matches(snapshot.BOM) {
			continue
		}
		if snapshot.BOM.Assets == nil {
			snapshot.BOM.Assets = []model.Asset{}
		}
		if snapshot.BOM.Relationships == nil {
			snapshot.BOM.Relationships = []model.Relationship{}
		}
		if snapshot.BOM.AccessPaths == nil {
			snapshot.BOM.AccessPaths = []model.AccessPath{}
		}
		items = append(items, organizationGraph{
			RepositoryID: repository.ID, Source: repository.Source, Revision: snapshot.BOM.Metadata.Revision,
			Assets: snapshot.BOM.Assets, Relationships: snapshot.BOM.Relationships, AccessPaths: snapshot.BOM.AccessPaths,
		})
	}
	writeJSON(w, http.StatusOK, listResponse[organizationGraph]{APIVersion: contracts.ControlPlaneAPIVersion, Items: items, NextCursor: encodeCursor(filter.cursorScope(), repositories.NextCursor)})
}

func (api *API) auditEvents(w http.ResponseWriter, request *http.Request) {
	if !rejectUnknownQueryParameters(w, request, "repositoryId", "eventName", "identityId", "limit", "cursor") {
		return
	}
	auditStore, ok := api.reader.(store.AuditStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "audit-store-unavailable", "audit history is unavailable")
		return
	}
	repositoryID, valid := requestBoundedQueryValue(w, request, "repositoryId", "invalid-repository-id", "repositoryId must be a single trimmed value of at most 200 bytes")
	if !valid {
		return
	}
	if repositoryID != "" {
		if !validRepositoryID(repositoryID) {
			writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
			return
		}
		if !authorizeRepository(w, request, repositoryID) {
			return
		}
	}
	eventName, valid := requestBoundedQueryValue(w, request, "eventName", "invalid-audit-filter", "audit filters must be single trimmed values of at most 200 bytes")
	if !valid {
		return
	}
	identityID, valid := requestBoundedQueryValue(w, request, "identityId", "invalid-audit-filter", "audit filters must be single trimmed values of at most 200 bytes")
	if !valid {
		return
	}
	scope := boundedCursorScope("audit-events", repositoryID, eventName, identityID)
	page, ok := requestPage(w, request, scope)
	if !ok {
		return
	}
	filter := store.AuditFilter{RepositoryID: repositoryID, EventName: eventName, IdentityID: identityID, Page: page}
	if repositoryID == "" {
		filter.RepositoryIDs = authorizedRepositoryIDs(request)
	}
	result, err := auditStore.ListAuditEvents(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "audit history is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, listResponse[store.AuditRecord]{APIVersion: contracts.ControlPlaneAPIVersion, Items: result.Items, NextCursor: encodeCursor(scope, result.NextCursor)})
}

func (api *API) snapshots(w http.ResponseWriter, request *http.Request) {
	if !rejectUnknownQueryParameters(w, request, "limit", "cursor") {
		return
	}
	repositoryID := request.PathValue("repositoryID")
	if !validRepositoryID(repositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if !authorizeRepository(w, request, repositoryID) {
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
	if !rejectUnknownQueryParameters(w, request) {
		return
	}
	repositoryID, snapshotID := request.PathValue("repositoryID"), request.PathValue("snapshotID")
	if !validRepositoryID(repositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if !authorizeRepository(w, request, repositoryID) {
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
	if !rejectUnknownQueryParameters(w, request) {
		return
	}
	id := request.PathValue("repositoryID")
	if !validRepositoryID(id) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if !authorizeRepository(w, request, id) {
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

func (api *API) repositoryDrift(w http.ResponseWriter, request *http.Request) {
	if !rejectUnknownQueryParameters(w, request, "beforeSnapshotId", "afterSnapshotId") {
		return
	}
	repositoryID := request.PathValue("repositoryID")
	if !validRepositoryID(repositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if !authorizeRepository(w, request, repositoryID) {
		return
	}
	beforeID, valid := requestBoundedQueryValue(w, request, "beforeSnapshotId", "invalid-snapshot-id", "beforeSnapshotId and afterSnapshotId must each be provided once")
	if !valid {
		return
	}
	afterID, valid := requestBoundedQueryValue(w, request, "afterSnapshotId", "invalid-snapshot-id", "beforeSnapshotId and afterSnapshotId must each be provided once")
	if !valid {
		return
	}
	if !validSnapshotID(beforeID) || !validSnapshotID(afterID) {
		writeError(w, http.StatusBadRequest, "invalid-snapshot-id", "beforeSnapshotId and afterSnapshotId must be valid snapshot IDs")
		return
	}
	before, err := api.reader.Snapshot(request.Context(), repositoryID, beforeID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "snapshot-not-found", "one or more snapshots were not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository snapshots are unavailable")
		return
	}
	after, err := api.reader.Snapshot(request.Context(), repositoryID, afterID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "snapshot-not-found", "one or more snapshots were not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository snapshots are unavailable")
		return
	}
	normalize.BOM(&before.BOM)
	normalize.BOM(&after.BOM)
	report := drift.Compare(before.BOM, after.BOM)
	if report.Changes == nil {
		report.Changes = []drift.Change{}
	}
	writeJSON(w, http.StatusOK, valueResponse[drift.Report]{APIVersion: contracts.ControlPlaneAPIVersion, Value: report})
}

func (api *API) findings(w http.ResponseWriter, request *http.Request) {
	if !rejectUnknownQueryParameters(w, request, "repositoryId", "severity", "limit", "cursor") {
		return
	}
	repositoryID, valid := requestBoundedQueryValue(w, request, "repositoryId", "invalid-repository-id", "repositoryId must be a single trimmed value of at most 200 bytes")
	if !valid {
		return
	}
	severity, valid := requestBoundedQueryValue(w, request, "severity", "invalid-severity", "severity must be a single trimmed value")
	if !valid {
		return
	}
	filter := store.FindingFilter{RepositoryID: repositoryID, Severity: strings.ToLower(severity)}
	if filter.RepositoryID != "" && !validRepositoryID(filter.RepositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if filter.RepositoryID != "" && !authorizeRepository(w, request, filter.RepositoryID) {
		return
	}
	filter.RepositoryIDs = authorizedRepositoryIDs(request)
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
	if !rejectUnknownQueryParameters(w, request, "repositoryId", "severity", "status", "limit", "cursor") {
		return
	}
	repositoryID, valid := requestBoundedQueryValue(w, request, "repositoryId", "invalid-repository-id", "repositoryId must be a single trimmed value of at most 200 bytes")
	if !valid {
		return
	}
	severity, valid := requestBoundedQueryValue(w, request, "severity", "invalid-severity", "severity must be a single trimmed value")
	if !valid {
		return
	}
	status, valid := requestBoundedQueryValue(w, request, "status", "invalid-lifecycle-status", "status must be a single trimmed value")
	if !valid {
		return
	}
	filter := store.FindingLifecycleFilter{
		RepositoryID: repositoryID,
		Severity:     strings.ToLower(severity),
		Status:       strings.ToLower(status),
	}
	if filter.RepositoryID != "" && !validRepositoryID(filter.RepositoryID) {
		writeError(w, http.StatusBadRequest, "invalid-repository-id", "repository ID is invalid")
		return
	}
	if filter.RepositoryID != "" && !authorizeRepository(w, request, filter.RepositoryID) {
		return
	}
	filter.RepositoryIDs = authorizedRepositoryIDs(request)
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

func requestBoundedQueryValue(w http.ResponseWriter, request *http.Request, name, code, message string) (string, bool) {
	values := request.URL.Query()[name]
	if len(values) > 1 {
		writeError(w, http.StatusBadRequest, code, message)
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	value := values[0]
	if value != strings.TrimSpace(value) || len(value) > 200 || strings.ContainsAny(value, "\x00\r\n") {
		writeError(w, http.StatusBadRequest, code, message)
		return "", false
	}
	return value, true
}

func rejectUnknownQueryParameters(w http.ResponseWriter, request *http.Request, allowed ...string) bool {
	allowlist := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowlist[name] = struct{}{}
	}
	for name := range request.URL.Query() {
		if _, ok := allowlist[name]; !ok {
			writeError(w, http.StatusBadRequest, "unknown-query-parameter", "query contains an unsupported parameter")
			return false
		}
	}
	return true
}

func requestPage(w http.ResponseWriter, request *http.Request, scope string) (store.PageRequest, bool) {
	page := store.PageRequest{Limit: 50}
	query := request.URL.Query()
	if len(query["limit"]) > 1 {
		writeError(w, http.StatusBadRequest, "invalid-limit", "limit must be provided at most once")
		return store.PageRequest{}, false
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, http.StatusBadRequest, "invalid-limit", "limit must be an integer between 1 and 200")
			return store.PageRequest{}, false
		}
		page.Limit = limit
	}
	if len(query["cursor"]) > 1 {
		writeError(w, http.StatusBadRequest, "invalid-cursor", "cursor must be provided at most once")
		return store.PageRequest{}, false
	}
	if raw := query.Get("cursor"); raw != "" {
		const maxDecodedCursorBytes = 512
		if len(raw) > base64.RawURLEncoding.EncodedLen(maxDecodedCursorBytes) {
			writeError(w, http.StatusBadRequest, "invalid-cursor", "cursor is invalid or unsupported")
			return store.PageRequest{}, false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		prefix := "v1\x00" + scope + "\x00"
		if err != nil || len(decoded) > maxDecodedCursorBytes || len(decoded) <= len(prefix) || !strings.HasPrefix(string(decoded), prefix) {
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
