package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestPublicAPIRoutesRejectUnknownQueryParameters(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "dev")
	for _, path := range []string{
		"/api/v1/repositories?typo=value",
		"/api/v1/graph?typo=value",
		"/api/v1/audit-events?typo=value",
		"/api/v1/repositories/repository-0000000000000001/snapshots?typo=value",
		"/api/v1/repositories/repository-0000000000000001/bom?typo=value",
		"/api/v1/repositories/repository-0000000000000001/snapshots/snapshot-0000000000000001/bom?typo=value",
		"/api/v1/repositories/repository-0000000000000001/drift?typo=value",
		"/api/v1/findings?typo=value",
		"/api/v1/finding-lifecycles?typo=value",
	} {
		response := performRequest(t, handler, "GET", path)
		assertResponse(t, response, 400, `"code":"unknown-query-parameter"`)
	}
}

func FuzzRejectUnknownQueryParameters(f *testing.F) {
	f.Add("", false)
	f.Add("allowed", true)
	f.Add("unknown", true)
	f.Add(strings.Repeat("a", 1024), true)

	f.Fuzz(func(t *testing.T, name string, present bool) {
		if len(name) > 8<<10 {
			t.Skip()
		}
		firstOK, firstStatus, firstBody := fuzzQueryAllowlist(name, present)
		secondOK, secondStatus, secondBody := fuzzQueryAllowlist(name, present)
		if firstOK != secondOK || firstStatus != secondStatus || firstBody != secondBody {
			t.Fatal("query allowlist is not deterministic")
		}
		expected := !present || name == "allowed"
		if firstOK != expected {
			t.Fatalf("rejectUnknownQueryParameters() accepted=%t, expected %t", firstOK, expected)
		}
		if !firstOK && firstStatus != 400 {
			t.Fatalf("rejected query status = %d, expected 400", firstStatus)
		}
	})
}

func fuzzQueryAllowlist(name string, present bool) (ok bool, status int, body string) {
	query := url.Values{}
	if present {
		query.Add(name, "value")
	}
	request := httptest.NewRequest("GET", "/?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	accepted := rejectUnknownQueryParameters(response, request, "allowed")
	return accepted, response.Code, response.Body.String()
}
