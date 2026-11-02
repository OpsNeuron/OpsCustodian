package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxFixtureBytes = 10 << 20

type operationMetrics struct {
	mu                 sync.Mutex
	successes          int64
	errors             int64
	latencies          []time.Duration
	unexpectedStatuses map[int]int64
}

type metricsSummary struct {
	Successes          int64            `json:"successes"`
	Errors             int64            `json:"errors"`
	LatencyP50MS       float64          `json:"latencyP50Ms"`
	LatencyP95MS       float64          `json:"latencyP95Ms"`
	LatencyP99MS       float64          `json:"latencyP99Ms"`
	LatencyMaxMS       float64          `json:"latencyMaxMs"`
	UnexpectedStatuses map[string]int64 `json:"unexpectedStatuses,omitempty"`
}

type probeSummary struct {
	StartedAt         string         `json:"startedAt"`
	FinishedAt        string         `json:"finishedAt"`
	DurationSeconds   int            `json:"durationSeconds"`
	ReadWorkers       int            `json:"readWorkers"`
	WriteWorkers      int            `json:"writeWorkers"`
	TargetReadRPS     int            `json:"targetReadRequestsPerSecond"`
	TargetWriteRPS    int            `json:"targetWriteRequestsPerSecond"`
	RequestsPerSecond float64        `json:"requestsPerSecond"`
	Read              metricsSummary `json:"read"`
	Write             metricsSummary `json:"write"`
	Readiness         metricsSummary `json:"readiness"`
}

type probeConfig struct {
	baseURL        string
	duration       time.Duration
	readWorkers    int
	writeWorkers   int
	readRPS        int
	writeRPS       int
	fixturePath    string
	revisionPrefix string
	token          string
}

func main() {
	config, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load probe configuration:", err)
		os.Exit(2)
	}
	fixture, err := readFixture(config.fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load probe fixture:", err)
		os.Exit(2)
	}

	summary, err := runProbe(config, fixture)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(summary); encodeErr != nil {
		fmt.Fprintln(os.Stderr, "encode load probe summary:", encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "load probe failed:", err)
		os.Exit(1)
	}
}

func parseConfig() (probeConfig, error) {
	var durationSeconds int
	config := probeConfig{}
	flag.StringVar(&config.baseURL, "base-url", "http://127.0.0.1:8080", "control-plane base URL")
	flag.IntVar(&durationSeconds, "duration-seconds", 300, "probe duration in seconds")
	flag.IntVar(&config.readWorkers, "read-workers", 16, "concurrent repository readers")
	flag.IntVar(&config.writeWorkers, "write-workers", 4, "concurrent snapshot writers")
	flag.IntVar(&config.readRPS, "read-rps", 100, "maximum aggregate repository reads per second")
	flag.IntVar(&config.writeRPS, "write-rps", 10, "maximum aggregate snapshot writes per second")
	flag.StringVar(&config.fixturePath, "fixture", "/fixtures/scope-expansion/agentbom.after.json", "Agent BOM fixture")
	flag.StringVar(&config.revisionPrefix, "revision-prefix", "soak", "generated revision prefix")
	flag.Parse()

	config.baseURL = strings.TrimRight(config.baseURL, "/")
	config.token = os.Getenv("OPSCUSTODIAN_TEST_API_TOKEN")
	config.duration = time.Duration(durationSeconds) * time.Second
	if config.token == "" {
		return probeConfig{}, errors.New("OPSCUSTODIAN_TEST_API_TOKEN is required")
	}
	if durationSeconds < 10 || durationSeconds > 14_400 {
		return probeConfig{}, errors.New("duration-seconds must be between 10 and 14400")
	}
	if config.readWorkers < 1 || config.readWorkers > 64 {
		return probeConfig{}, errors.New("read-workers must be between 1 and 64")
	}
	if config.writeWorkers < 1 || config.writeWorkers > 16 {
		return probeConfig{}, errors.New("write-workers must be between 1 and 16")
	}
	if config.readWorkers+config.writeWorkers > 64 {
		return probeConfig{}, errors.New("combined worker count must not exceed 64")
	}
	if config.readRPS < 1 || config.readRPS > 5_000 {
		return probeConfig{}, errors.New("read-rps must be between 1 and 5000")
	}
	if config.writeRPS < 1 || config.writeRPS > 1_000 {
		return probeConfig{}, errors.New("write-rps must be between 1 and 1000")
	}
	if config.baseURL == "" || config.fixturePath == "" || !validRevisionPrefix(config.revisionPrefix) {
		return probeConfig{}, errors.New("base-url, fixture, and an alphanumeric revision-prefix are required")
	}
	return config, nil
}

func validRevisionPrefix(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func readFixture(path string) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxFixtureBytes {
		return nil, errors.New("fixture exceeds 10 MiB limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("fixture must contain exactly one JSON document")
	}
	if metadata, ok := document["metadata"].(map[string]any); !ok || metadata == nil {
		return nil, errors.New("fixture metadata is required")
	}
	return document, nil
}

func runProbe(config probeConfig, fixture map[string]any) (probeSummary, error) {
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), config.duration)
	defer cancel()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = config.readWorkers + config.writeWorkers + 8
	transport.MaxIdleConnsPerHost = transport.MaxIdleConns
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	defer transport.CloseIdleConnections()

	readMetrics := &operationMetrics{}
	writeMetrics := &operationMetrics{}
	readinessMetrics := &operationMetrics{}
	var sequence atomic.Uint64
	var workers sync.WaitGroup

	for worker := 0; worker < config.readWorkers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runPaced(ctx, workerInterval(config.readWorkers, config.readRPS), func() {
				performRequest(client, http.MethodGet, config.baseURL+"/api/v1/repositories", config.token, nil, http.StatusOK, readMetrics)
			})
		}()
	}
	for worker := 0; worker < config.writeWorkers; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			runPaced(ctx, workerInterval(config.writeWorkers, config.writeRPS), func() {
				revision := config.revisionPrefix + "-" + strconv.Itoa(worker+1) + "-" + strconv.FormatUint(sequence.Add(1), 10)
				payload, err := fixtureWithRevision(fixture, revision)
				if err != nil {
					writeMetrics.record(0, false, 0)
					return
				}
				performRequest(client, http.MethodPost, config.baseURL+"/api/v1/snapshots", config.token, payload, http.StatusCreated, writeMetrics)
			})
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			performRequest(client, http.MethodGet, config.baseURL+"/readyz", "", nil, http.StatusOK, readinessMetrics)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	workers.Wait()
	finished := time.Now().UTC()
	read := readMetrics.summary()
	write := writeMetrics.summary()
	readiness := readinessMetrics.summary()
	total := read.Successes + write.Successes
	summary := probeSummary{
		StartedAt: started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano),
		DurationSeconds: int(config.duration / time.Second), ReadWorkers: config.readWorkers, WriteWorkers: config.writeWorkers,
		TargetReadRPS: config.readRPS, TargetWriteRPS: config.writeRPS,
		RequestsPerSecond: float64(total) / config.duration.Seconds(), Read: read, Write: write, Readiness: readiness,
	}
	if read.Errors != 0 || write.Errors != 0 || readiness.Errors != 0 {
		return summary, errors.New("one or more requests failed")
	}
	if read.Successes < int64(config.readWorkers) || write.Successes < int64(config.writeWorkers) || readiness.Successes < 1 {
		return summary, errors.New("insufficient successful requests")
	}
	return summary, nil
}

func workerInterval(workers, requestsPerSecond int) time.Duration {
	interval := time.Second * time.Duration(workers) / time.Duration(requestsPerSecond)
	if interval < time.Millisecond {
		return time.Millisecond
	}
	return interval
}

func runPaced(ctx context.Context, interval time.Duration, operation func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operation()
		}
	}
}

func fixtureWithRevision(fixture map[string]any, revision string) ([]byte, error) {
	copyBytes, err := json.Marshal(fixture)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(copyBytes, &document); err != nil {
		return nil, err
	}
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return nil, errors.New("fixture metadata is required")
	}
	metadata["revision"] = revision
	return json.Marshal(document)
}

func performRequest(client *http.Client, method, url, token string, body []byte, expectedStatus int, metrics *operationMetrics) {
	started := time.Now()
	requestContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, url, bytes.NewReader(body))
	if err != nil {
		metrics.record(time.Since(started), false, 0)
		return
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	latency := time.Since(started)
	if err != nil {
		metrics.record(latency, false, 0)
		return
	}
	_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	success := response.StatusCode == expectedStatus && copyErr == nil && closeErr == nil
	metrics.record(latency, success, response.StatusCode)
}

func (metrics *operationMetrics) record(latency time.Duration, success bool, status int) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.latencies = append(metrics.latencies, latency)
	if success {
		metrics.successes++
		return
	}
	metrics.errors++
	if status != 0 {
		if metrics.unexpectedStatuses == nil {
			metrics.unexpectedStatuses = make(map[int]int64)
		}
		metrics.unexpectedStatuses[status]++
	}
}

func (metrics *operationMetrics) summary() metricsSummary {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	latencies := append([]time.Duration(nil), metrics.latencies...)
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	statuses := make(map[string]int64, len(metrics.unexpectedStatuses))
	for status, count := range metrics.unexpectedStatuses {
		statuses[strconv.Itoa(status)] = count
	}
	return metricsSummary{
		Successes: metrics.successes, Errors: metrics.errors,
		LatencyP50MS:       durationMilliseconds(percentile(latencies, 50)),
		LatencyP95MS:       durationMilliseconds(percentile(latencies, 95)),
		LatencyP99MS:       durationMilliseconds(percentile(latencies, 99)),
		LatencyMaxMS:       durationMilliseconds(percentile(latencies, 100)),
		UnexpectedStatuses: statuses,
	}
}

func percentile(sorted []time.Duration, percent int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (percent*len(sorted)+99)/100 - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value.Microseconds()) / 1000
}
