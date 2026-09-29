package server

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestRequestPageRejectsAmbiguousOrOversizedInput(t *testing.T) {
	validCursor := encodeCursor("fuzz-scope", "repository-0000000000000001")
	tests := []struct {
		name, cursor, limit string
		duplicate           bool
	}{
		{name: "empty cursor payload", cursor: base64.RawURLEncoding.EncodeToString([]byte("v1\x00fuzz-scope\x00"))},
		{name: "oversized encoded cursor", cursor: strings.Repeat("A", base64.RawURLEncoding.EncodedLen(512)+1)},
		{name: "duplicate cursor", cursor: validCursor, duplicate: true},
		{name: "duplicate limit", limit: "50", duplicate: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, accepted, status, body := fuzzRequestPage(test.cursor, test.limit, test.duplicate)
			if accepted || status != 400 || !strings.Contains(body, `"code":"invalid-`) {
				t.Fatalf("requestPage() accepted=%t status=%d body=%s", accepted, status, body)
			}
		})
	}
}

func FuzzRequestPage(f *testing.F) {
	f.Add("", "", false)
	f.Add("invalid", "0", false)
	f.Add(encodeCursor("fuzz-scope", "repository-0000000000000001"), "200", false)
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("v1\x00other-scope\x00value")), "1", false)
	f.Add(strings.Repeat("A", base64.RawURLEncoding.EncodedLen(512)+1), "50", true)

	f.Fuzz(func(t *testing.T, cursor, limit string, duplicate bool) {
		if len(cursor) > 8<<10 || len(limit) > 1<<10 {
			t.Skip()
		}
		firstPage, firstOK, firstStatus, firstBody := fuzzRequestPage(cursor, limit, duplicate)
		secondPage, secondOK, secondStatus, secondBody := fuzzRequestPage(cursor, limit, duplicate)
		if firstOK != secondOK || firstStatus != secondStatus || firstBody != secondBody || !reflect.DeepEqual(firstPage, secondPage) {
			t.Fatal("pagination parsing is not deterministic")
		}
		if !firstOK {
			if firstStatus != 400 {
				t.Fatalf("rejected pagination status = %d, expected 400", firstStatus)
			}
			return
		}
		if duplicate && (cursor != "" || limit != "") {
			t.Fatal("accepted duplicate pagination parameters")
		}
		if firstPage.Limit < 1 || firstPage.Limit > 200 {
			t.Fatalf("accepted limit outside bounds: %d", firstPage.Limit)
		}
		if cursor != "" && firstPage.Cursor == "" {
			t.Fatal("accepted cursor without a keyset payload")
		}
	})
}

func fuzzRequestPage(cursor, limit string, duplicate bool) (page store.PageRequest, ok bool, status int, body string) {
	query := url.Values{}
	if cursor != "" {
		query.Add("cursor", cursor)
		if duplicate {
			query.Add("cursor", cursor)
		}
	}
	if limit != "" {
		query.Add("limit", limit)
		if duplicate {
			query.Add("limit", limit)
		}
	}
	request := httptest.NewRequest("GET", "/?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	result, accepted := requestPage(response, request, "fuzz-scope")
	return result, accepted, response.Code, response.Body.String()
}
