package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/store"
)

type API struct {
	reader       store.Reader
	buildVersion string
}

type listResponse[T any] struct {
	APIVersion string `json:"apiVersion"`
	Items      []T    `json:"items"`
}

type valueResponse[T any] struct {
	APIVersion string `json:"apiVersion"`
	Value      T      `json:"value"`
}

type errorResponse struct {
	APIVersion string `json:"apiVersion"`
	Error      struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewHandler(reader store.Reader, buildVersion string) http.Handler {
	api := &API{reader: reader, buildVersion: buildVersion}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /api/v1/contracts", api.contracts)
	mux.HandleFunc("GET /api/v1/repositories", api.repositories)
	mux.HandleFunc("GET /api/v1/repositories/{repositoryID}/bom", api.latestBOM)
	mux.HandleFunc("GET /api/v1/findings", api.findings)
	return securityHeaders(mux)
}

func (api *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *API) contracts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, valueResponse[contracts.Info]{APIVersion: contracts.ControlPlaneAPIVersion, Value: contracts.BuildInfo(api.buildVersion)})
}

func (api *API) repositories(w http.ResponseWriter, request *http.Request) {
	items, err := api.reader.ListRepositories(request.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "repository inventory is unavailable")
		return
	}
	if items == nil {
		items = []store.RepositorySummary{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.RepositorySummary]{APIVersion: contracts.ControlPlaneAPIVersion, Items: items})
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
	items, err := api.reader.ListFindings(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store-read-failed", "finding inventory is unavailable")
		return
	}
	if items == nil {
		items = []store.FindingRecord{}
	}
	writeJSON(w, http.StatusOK, listResponse[store.FindingRecord]{APIVersion: contracts.ControlPlaneAPIVersion, Items: items})
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
	if !strings.HasPrefix(value, "repository-") || len(value) != len("repository-")+16 {
		return false
	}
	for _, character := range value[len("repository-"):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validSeverity(value string) bool {
	return value == "info" || value == "low" || value == "medium" || value == "high" || value == "critical"
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
