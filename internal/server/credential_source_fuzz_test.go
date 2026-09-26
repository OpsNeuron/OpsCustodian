package server

import (
	"encoding/json"
	"testing"
)

func FuzzParseBearerCredentialsJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`[{"id":"reader","token":"0123456789abcdef0123456789abcdef","scopes":["inventory:read"]}]`),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`{"id":"not-an-array"}`),
		[]byte(`[{"unknown":true}]`),
		[]byte("[{}]\n{}"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 1<<20 {
			t.Skip()
		}
		credentials, err := ParseBearerCredentialsJSON(content)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(credentials)
		if err != nil {
			t.Fatalf("marshal accepted credentials: %v", err)
		}
		reparsed, err := ParseBearerCredentialsJSON(encoded)
		if err != nil || len(reparsed) != len(credentials) {
			t.Fatalf("accepted credentials are not round-trip stable: %v", err)
		}
	})
}
