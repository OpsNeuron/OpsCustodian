package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestFilterEndpointsRejectDuplicateParameters(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "dev")
	tests := []struct {
		path, code string
	}{
		{path: "/api/v1/graph?owner=one&owner=two", code: "invalid-graph-filter"},
		{path: "/api/v1/audit-events?eventName=one&eventName=two", code: "invalid-audit-filter"},
		{path: "/api/v1/findings?severity=high&severity=low", code: "invalid-severity"},
		{path: "/api/v1/finding-lifecycles?status=introduced&status=resolved", code: "invalid-lifecycle-status"},
		{path: "/api/v1/findings?repositoryId=repository-0000000000000001&repositoryId=repository-0000000000000002", code: "invalid-repository-id"},
		{path: "/api/v1/repositories/repository-0000000000000001/drift?beforeSnapshotId=snapshot-0000000000000001&beforeSnapshotId=snapshot-0000000000000002&afterSnapshotId=snapshot-0000000000000003", code: "invalid-snapshot-id"},
	}
	for _, test := range tests {
		response := performRequest(t, handler, "GET", test.path)
		assertResponse(t, response, 400, `"code":"`+test.code+`"`)
	}
}

func FuzzRequestBoundedQueryValue(f *testing.F) {
	f.Add("", false, false)
	f.Add("high", true, false)
	f.Add(" high", true, false)
	f.Add(strings.Repeat("a", 201), true, false)
	f.Add("value", true, true)

	f.Fuzz(func(t *testing.T, value string, present, duplicate bool) {
		if len(value) > 8<<10 {
			t.Skip()
		}
		firstValue, firstOK, firstStatus, firstBody := fuzzBoundedQueryValue(value, present, duplicate)
		secondValue, secondOK, secondStatus, secondBody := fuzzBoundedQueryValue(value, present, duplicate)
		if firstValue != secondValue || firstOK != secondOK || firstStatus != secondStatus || firstBody != secondBody {
			t.Fatal("query validation is not deterministic")
		}
		valid := !present || !duplicate && value == strings.TrimSpace(value) && len(value) <= 200 && !strings.ContainsAny(value, "\x00\r\n")
		if firstOK != valid {
			t.Fatalf("requestBoundedQueryValue() accepted=%t, expected %t", firstOK, valid)
		}
		if !firstOK && firstStatus != 400 {
			t.Fatalf("rejected query status = %d, expected 400", firstStatus)
		}
	})
}

func fuzzBoundedQueryValue(value string, present, duplicate bool) (result string, ok bool, status int, body string) {
	query := url.Values{}
	if present {
		query.Add("filter", value)
		if duplicate {
			query.Add("filter", value)
		}
	}
	request := httptest.NewRequest("GET", "/?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	result, accepted := requestBoundedQueryValue(response, request, "filter", "invalid-filter", "filter is invalid")
	return result, accepted, response.Code, response.Body.String()
}
