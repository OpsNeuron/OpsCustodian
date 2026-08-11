package policy

import (
	"strings"
	"testing"
)

func TestDecodeOPAResponseNormalizesAndValidatesDecision(t *testing.T) {
	content := []byte(`{"result":[{"expressions":[{"value":{"deny":[{"rule":"production-approval","title":"Approval required","message":"production access requires human approval","agentId":"agent:deployer"}],"warn":[]}}]}]}`)

	decision, err := decodeOPAResponse(content, "data.opscustodian.decision")
	if err != nil {
		t.Fatalf("decodeOPAResponse() error = %v", err)
	}
	if len(decision.Deny) != 1 || decision.Deny[0].Severity != "high" || !strings.HasPrefix(decision.Deny[0].ID, "policy-") {
		t.Fatalf("unexpected normalized decision: %#v", decision)
	}
	if decision.Warn == nil || len(decision.Warn) != 0 {
		t.Fatalf("expected an explicit empty warn array, got %#v", decision.Warn)
	}
}

func TestDecodeOPAResponseRejectsInvalidOutput(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		contains string
	}{
		{name: "malformed JSON", content: `{`, contains: "decode OPA response"},
		{name: "undefined query", content: `{"result":[]}`, contains: `returned no decision`},
		{name: "missing decision arrays", content: `{"result":[{"expressions":[{"value":{}}]}]}`, contains: "invalid policy decision"},
		{name: "invalid decision shape", content: `{"result":[{"expressions":[{"value":"allow"}]}]}`, contains: "decode policy decision"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeOPAResponse([]byte(test.content), "data.opscustodian.decision")
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("decodeOPAResponse() error = %v, want containing %q", err, test.contains)
			}
		})
	}
}

func TestLimitedBufferBoundsExternalProcessOutput(t *testing.T) {
	buffer := newLimitedBuffer(5)
	written, err := buffer.Write([]byte("12345678"))
	if err != nil || written != 8 {
		t.Fatalf("Write() = (%d, %v), want (8, nil)", written, err)
	}
	if buffer.String() != "12345" || !buffer.Truncated() {
		t.Fatalf("unexpected bounded buffer state: value=%q truncated=%t", buffer.String(), buffer.Truncated())
	}
	if written, err := buffer.Write([]byte("more")); err != nil || written != 4 || buffer.String() != "12345" {
		t.Fatalf("second Write() = (%d, %v), value=%q", written, err, buffer.String())
	}
}
