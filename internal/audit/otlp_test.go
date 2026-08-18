package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExportOTLPHTTPUsesOfficialLogsJSONShape(t *testing.T) {
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/logs" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected headers: %#v", r.Header)
		}
		captured, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	when := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	events := []Event{newEvent(when.Format(time.RFC3339Nano), "opscustodian.scan.completed", 9, "completed", map[string]any{
		"opscustodian.asset.count": 2, "opscustodian.risk.factors": []string{"wildcard"},
	})}
	err := ExportOTLPHTTP(context.Background(), events, OTLPHTTPOptions{
		Endpoint: server.URL + "/v1/logs", AllowInsecure: true, ObservedAt: when.Add(time.Second),
		Headers: map[string]string{"Authorization": "Bearer test-token"},
	})
	if err != nil {
		t.Fatalf("ExportOTLPHTTP() error: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(captured, &request); err != nil {
		t.Fatalf("invalid OTLP JSON: %v", err)
	}
	text := string(captured)
	for _, expected := range []string{`"resourceLogs"`, `"scopeLogs"`, `"logRecords"`, `"eventName":"opscustodian.scan.completed"`, `"timeUnixNano":"1787054400000000000"`, `"observedTimeUnixNano":"1787054401000000000"`, `"opscustodian.schema.version"`, `"intValue":"2"`, `"arrayValue"`} {
		if !strings.Contains(text, expected) {
			t.Errorf("OTLP payload missing %s: %s", expected, text)
		}
	}
}

func TestExportOTLPHTTPSecurityGuardrails(t *testing.T) {
	event := newEvent("2026-08-18T12:00:00Z", "opscustodian.scan.completed", 9, "completed", nil)
	for name, opts := range map[string]OTLPHTTPOptions{
		"http requires opt in": {Endpoint: "http://collector:4318/v1/logs"},
		"userinfo rejected":    {Endpoint: "https://token@collector/v1/logs"},
		"query rejected":       {Endpoint: "https://collector/v1/logs?token=value"},
		"timeout bounded":      {Endpoint: "https://collector/v1/logs", Timeout: 61 * time.Second},
		"host header rejected": {Endpoint: "https://collector/v1/logs", Headers: map[string]string{"Host": "evil"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ExportOTLPHTTP(context.Background(), []Event{event}, opts); err == nil {
				t.Fatal("expected guardrail error")
			}
		})
	}
}

func TestParseOTLPHeaders(t *testing.T) {
	headers, err := ParseOTLPHeaders("authorization=Bearer%20token,x-tenant=platform")
	if err != nil || headers["authorization"] != "Bearer token" || headers["x-tenant"] != "platform" {
		t.Fatalf("ParseOTLPHeaders() = %#v, %v", headers, err)
	}
	if _, err := ParseOTLPHeaders("broken"); err == nil {
		t.Fatal("accepted malformed OTLP headers")
	}
}

func TestExportOTLPHTTPRejectsPartialSuccessAndRedirect(t *testing.T) {
	event := newEvent("2026-08-18T12:00:00Z", "opscustodian.scan.completed", 9, "completed", nil)
	partial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"invalid"}}`))
	}))
	defer partial.Close()
	if err := ExportOTLPHTTP(context.Background(), []Event{event}, OTLPHTTPOptions{Endpoint: partial.URL, AllowInsecure: true}); err == nil || !strings.Contains(err.Error(), "partially rejected 1") {
		t.Fatalf("partial success error = %v", err)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, partial.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := ExportOTLPHTTP(context.Background(), []Event{event}, OTLPHTTPOptions{Endpoint: redirect.URL, AllowInsecure: true, Client: redirect.Client()}); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect error = %v", err)
	}
}
