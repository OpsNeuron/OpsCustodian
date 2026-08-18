package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultOTLPTimeout = 10 * time.Second

type OTLPHTTPOptions struct {
	Endpoint      string
	Headers       map[string]string
	Timeout       time.Duration
	AllowInsecure bool
	ObservedAt    time.Time
	Client        *http.Client
}

type otlpExportLogsRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

// ParseOTLPHeaders parses the standard OTEL_EXPORTER_OTLP_*_HEADERS format.
func ParseOTLPHeaders(raw string) (map[string]string, error) {
	result := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}
	for _, member := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(member, "=")
		if !ok {
			return nil, fmt.Errorf("invalid OTLP header member")
		}
		key, err := url.PathUnescape(strings.TrimSpace(key))
		if err != nil {
			return nil, fmt.Errorf("decode OTLP header name: %w", err)
		}
		value, err = url.PathUnescape(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("decode OTLP header value for %q: %w", key, err)
		}
		if err := validateOTLPHeader(key); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScopeLogs struct {
	Scope      InstrumentationScope `json:"scope"`
	LogRecords []otlpLogRecord      `json:"logRecords"`
}

type otlpLogRecord struct {
	TimeUnixNano         string         `json:"timeUnixNano"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	SeverityNumber       int            `json:"severityNumber"`
	Body                 otlpAnyValue   `json:"body,omitempty"`
	Attributes           []otlpKeyValue `json:"attributes,omitempty"`
	EventName            string         `json:"eventName"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue *string         `json:"stringValue,omitempty"`
	IntValue    *string         `json:"intValue,omitempty"`
	BoolValue   *bool           `json:"boolValue,omitempty"`
	DoubleValue *float64        `json:"doubleValue,omitempty"`
	ArrayValue  *otlpArrayValue `json:"arrayValue,omitempty"`
}

type otlpArrayValue struct {
	Values []otlpAnyValue `json:"values"`
}

type otlpExportLogsResponse struct {
	PartialSuccess struct {
		RejectedLogRecords string `json:"rejectedLogRecords"`
	} `json:"partialSuccess"`
}

// ExportOTLPHTTP exports one batch using the standard OTLP/HTTP JSON mapping.
// It deliberately performs one attempt: orchestration or a Collector should own
// durable queuing and retry policy rather than hiding it in a CLI invocation.
func ExportOTLPHTTP(ctx context.Context, events []Event, opts OTLPHTTPOptions) error {
	endpoint, err := validateOTLPEndpoint(opts.Endpoint, opts.AllowInsecure)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	observedAt := opts.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	wireRequest, err := toOTLPRequest(events, observedAt)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(wireRequest)
	if err != nil {
		return fmt.Errorf("encode OTLP logs request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpsCustodian OTLP-HTTP-JSON exporter")
	for name, value := range opts.Headers {
		if err := validateOTLPHeader(name); err != nil {
			return err
		}
		req.Header.Set(name, value)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultOTLPTimeout
	}
	if timeout < 0 || timeout > time.Minute {
		return fmt.Errorf("OTLP timeout must be between 1ns and 1m")
	}
	client := http.Client{}
	if opts.Client != nil {
		client = *opts.Client
	}
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("export OTLP logs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("read OTLP response: %w", err)
	}
	if len(bytes.TrimSpace(body)) > 0 {
		var result otlpExportLogsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("decode OTLP response: %w", err)
		}
		if result.PartialSuccess.RejectedLogRecords != "" && result.PartialSuccess.RejectedLogRecords != "0" {
			return fmt.Errorf("OTLP endpoint partially rejected %s log records", result.PartialSuccess.RejectedLogRecords)
		}
	}
	return nil
}

func toOTLPRequest(events []Event, observedAt time.Time) (otlpExportLogsRequest, error) {
	first := events[0]
	records := make([]otlpLogRecord, 0, len(events))
	observed := strconv.FormatInt(observedAt.UnixNano(), 10)
	for _, event := range events {
		occurred, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			return otlpExportLogsRequest{}, fmt.Errorf("event %q has invalid timestamp: %w", event.EventName, err)
		}
		attributes := cloneAttributes(event.Attributes)
		attributes["opscustodian.schema.version"] = event.SchemaVersion
		records = append(records, otlpLogRecord{
			TimeUnixNano: strconv.FormatInt(occurred.UnixNano(), 10), ObservedTimeUnixNano: observed,
			SeverityNumber: event.SeverityNumber, Body: otlpValue(event.Body),
			Attributes: otlpAttributes(attributes), EventName: event.EventName,
		})
	}
	return otlpExportLogsRequest{ResourceLogs: []otlpResourceLogs{{
		Resource:  otlpResource{Attributes: otlpAttributes(first.Resource)},
		ScopeLogs: []otlpScopeLogs{{Scope: first.InstrumentationScope, LogRecords: records}},
	}}}, nil
}

func otlpAttributes(values map[string]any) []otlpKeyValue {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]otlpKeyValue, 0, len(keys))
	for _, key := range keys {
		result = append(result, otlpKeyValue{Key: key, Value: otlpValue(values[key])})
	}
	return result
}

func otlpValue(value any) otlpAnyValue {
	switch typed := value.(type) {
	case string:
		return otlpAnyValue{StringValue: &typed}
	case bool:
		return otlpAnyValue{BoolValue: &typed}
	case int:
		v := strconv.Itoa(typed)
		return otlpAnyValue{IntValue: &v}
	case int64:
		v := strconv.FormatInt(typed, 10)
		return otlpAnyValue{IntValue: &v}
	case float64:
		return otlpAnyValue{DoubleValue: &typed}
	case []string:
		values := make([]otlpAnyValue, 0, len(typed))
		for _, item := range typed {
			values = append(values, otlpValue(item))
		}
		return otlpAnyValue{ArrayValue: &otlpArrayValue{Values: values}}
	default:
		v := fmt.Sprint(value)
		return otlpAnyValue{StringValue: &v}
	}
}

func cloneAttributes(values map[string]any) map[string]any {
	result := make(map[string]any, len(values)+1)
	for key, value := range values {
		result[key] = value
	}
	return result
}

func validateOTLPEndpoint(raw string, allowInsecure bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", fmt.Errorf("OTLP endpoint must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("OTLP endpoint must not contain userinfo, query, or fragment")
	}
	if parsed.Scheme == "http" && !allowInsecure {
		return "", fmt.Errorf("insecure OTLP endpoint requires --allow-insecure-otlp")
	}
	return parsed.String(), nil
}

func validateOTLPHeader(name string) error {
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
	blocked := map[string]bool{
		"": true, "Host": true, "Content-Length": true, "Connection": true,
		"Keep-Alive": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
		"Transfer-Encoding": true, "Upgrade": true,
	}
	if blocked[canonical] {
		return fmt.Errorf("OTLP header %q is not allowed", name)
	}
	return nil
}
