package policy

import "testing"

func FuzzDecodeOPAResponse(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"result":[{"expressions":[{"value":{"allowed":true,"deny":[],"warn":[]}}]}]}`),
		[]byte(`{"result":[]}`),
		[]byte(`null`),
		[]byte(`{"result":[{"expressions":[{"value":null}]}]}`),
		[]byte(`{"result":[{"expressions":[{"value":{"allowed":false,"deny":[{"id":"x"}]}}]}]}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 4<<20 {
			t.Skip()
		}
		decision, err := decodeOPAResponse(content, "data.opscustodian.decision")
		if err != nil {
			return
		}
		if err := decision.Validate(); err != nil {
			t.Fatalf("decoder returned an invalid decision: %v", err)
		}
	})
}
