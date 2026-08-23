package ingestion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/opscustodian/opscustodian/internal/boundary"
)

const (
	RepositorySetAPIVersion       = "opscustodian.dev/ingestion/v1alpha1"
	RepositorySetKind             = "RepositorySet"
	MaximumRepositorySetFileBytes = 1 << 20
	maximumRepositoryFileSize     = 100 << 20
)

type RepositorySetDocument struct {
	APIVersion   string                     `json:"apiVersion"`
	Kind         string                     `json:"kind"`
	Schedule     RepositoryScheduleDocument `json:"schedule"`
	Repositories []Repository               `json:"repositories"`
}

type RepositoryScheduleDocument struct {
	Interval          string              `json:"interval"`
	MaxJitter         string              `json:"maxJitter,omitempty"`
	MaxConcurrency    int                 `json:"maxConcurrency"`
	RepositoryTimeout string              `json:"repositoryTimeout,omitempty"`
	Retry             RetryPolicyDocument `json:"retry,omitempty"`
}

type RetryPolicyDocument struct {
	MaxAttempts    int    `json:"maxAttempts"`
	InitialBackoff string `json:"initialBackoff,omitempty"`
	MaxBackoff     string `json:"maxBackoff,omitempty"`
}

type RepositorySet struct {
	Repositories      []Repository
	Interval          time.Duration
	MaxJitter         time.Duration
	MaxConcurrency    int
	RepositoryTimeout time.Duration
	Retry             RetryPolicy
}

func LoadRepositorySet(path string) (RepositorySet, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return RepositorySet{}, fmt.Errorf("repository set path must be a clean absolute path")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return RepositorySet{}, fmt.Errorf("inspect repository set: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return RepositorySet{}, fmt.Errorf("repository set must be a regular non-symlink file")
	}
	if linkInfo.Size() > MaximumRepositorySetFileBytes {
		return RepositorySet{}, fmt.Errorf("repository set exceeds %d bytes", MaximumRepositorySetFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return RepositorySet{}, fmt.Errorf("open repository set: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return RepositorySet{}, fmt.Errorf("inspect opened repository set: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return RepositorySet{}, fmt.Errorf("repository set changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaximumRepositorySetFileBytes+1))
	if err != nil {
		return RepositorySet{}, fmt.Errorf("read repository set: %w", err)
	}
	if int64(len(content)) > MaximumRepositorySetFileBytes {
		return RepositorySet{}, fmt.Errorf("repository set exceeds %d bytes", MaximumRepositorySetFileBytes)
	}
	return ParseRepositorySet(content)
}

func ParseRepositorySet(content []byte) (RepositorySet, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document RepositorySetDocument
	if err := decoder.Decode(&document); err != nil {
		return RepositorySet{}, fmt.Errorf("parse repository set JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RepositorySet{}, fmt.Errorf("repository set must contain exactly one JSON value")
	}
	return validateRepositorySet(document)
}

func validateRepositorySet(document RepositorySetDocument) (RepositorySet, error) {
	if document.APIVersion != RepositorySetAPIVersion || document.Kind != RepositorySetKind {
		return RepositorySet{}, fmt.Errorf("unsupported repository set apiVersion or kind")
	}
	if len(document.Repositories) == 0 || len(document.Repositories) > 10000 {
		return RepositorySet{}, fmt.Errorf("repository set must contain between 1 and 10000 repositories")
	}
	interval, err := parseRequiredDuration("schedule.interval", document.Schedule.Interval)
	if err != nil || interval < MinimumScheduleInterval || interval > MaximumScheduleInterval {
		return RepositorySet{}, fmt.Errorf("schedule.interval must be between %s and %s", MinimumScheduleInterval, MaximumScheduleInterval)
	}
	maxJitter, err := parseOptionalDuration("schedule.maxJitter", document.Schedule.MaxJitter)
	if err != nil || maxJitter < 0 || maxJitter > interval {
		return RepositorySet{}, fmt.Errorf("schedule.maxJitter must be between zero and schedule.interval")
	}
	repositoryTimeout, err := parseOptionalDuration("schedule.repositoryTimeout", document.Schedule.RepositoryTimeout)
	if err != nil || repositoryTimeout < 0 || repositoryTimeout > MaximumScheduleInterval {
		return RepositorySet{}, fmt.Errorf("schedule.repositoryTimeout must be between zero and %s", MaximumScheduleInterval)
	}
	if document.Schedule.MaxConcurrency < 1 || document.Schedule.MaxConcurrency > 1000 {
		return RepositorySet{}, fmt.Errorf("schedule.maxConcurrency must be between 1 and 1000")
	}
	retry, err := parseRetryPolicy(document.Schedule.Retry)
	if err != nil {
		return RepositorySet{}, err
	}

	repositories := cloneRepositories(document.Repositories)
	seen := make(map[string]struct{}, len(repositories))
	for index := range repositories {
		repository := &repositories[index]
		if err := validateSafeString(repository.Source, 2048); err != nil {
			return RepositorySet{}, fmt.Errorf("repositories[%d].source is invalid", index)
		}
		if _, exists := seen[repository.Source]; exists {
			return RepositorySet{}, fmt.Errorf("duplicate repository source %q", repository.Source)
		}
		seen[repository.Source] = struct{}{}
		if repository.MaxFileSize < 0 || repository.MaxFileSize > maximumRepositoryFileSize {
			return RepositorySet{}, fmt.Errorf("repositories[%d].maxFileSize must be between zero and %d", index, maximumRepositoryFileSize)
		}
		if _, err := boundary.Parse(repository.Boundaries); err != nil {
			return RepositorySet{}, fmt.Errorf("repositories[%d].boundaries: %w", index, err)
		}
		switch repository.Connector {
		case LocalConnectorName:
			if repository.Ref != "" || repository.CredentialReference != "" {
				return RepositorySet{}, fmt.Errorf("repositories[%d] local connector does not accept ref or credentialReference", index)
			}
			if err := validateSafeString(repository.Revision, 512); err != nil {
				return RepositorySet{}, fmt.Errorf("repositories[%d].revision is invalid", index)
			}
			if !filepath.IsAbs(repository.Location) || filepath.Clean(repository.Location) != repository.Location {
				return RepositorySet{}, fmt.Errorf("repositories[%d].location must be a clean absolute path", index)
			}
		case GitHubConnectorName:
			if _, _, err := ParseGitHubSource(repository.Source); err != nil {
				return RepositorySet{}, fmt.Errorf("repositories[%d].source: %w", index, err)
			}
			if repository.Location != "" || repository.Revision != "" {
				return RepositorySet{}, fmt.Errorf("repositories[%d] GitHub connector does not accept location or revision", index)
			}
			if err := validateGitHubRef(repository.Ref); err != nil {
				return RepositorySet{}, fmt.Errorf("repositories[%d].ref: %w", index, err)
			}
			if repository.CredentialReference != "" {
				if _, err := GitHubCredentialEnvironmentName(repository.CredentialReference); err != nil {
					return RepositorySet{}, fmt.Errorf("repositories[%d].credentialReference: %w", index, err)
				}
			}
		default:
			return RepositorySet{}, fmt.Errorf("repositories[%d].connector %q is unsupported", index, repository.Connector)
		}
	}
	return RepositorySet{
		Repositories: repositories, Interval: interval, MaxJitter: maxJitter,
		MaxConcurrency: document.Schedule.MaxConcurrency, RepositoryTimeout: repositoryTimeout, Retry: retry,
	}, nil
}

func parseRetryPolicy(document RetryPolicyDocument) (RetryPolicy, error) {
	if document.MaxAttempts < 1 || document.MaxAttempts > 10 {
		return RetryPolicy{}, fmt.Errorf("schedule.retry.maxAttempts must be between 1 and 10")
	}
	initial, err := parseOptionalDuration("schedule.retry.initialBackoff", document.InitialBackoff)
	if err != nil {
		return RetryPolicy{}, err
	}
	maximum, err := parseOptionalDuration("schedule.retry.maxBackoff", document.MaxBackoff)
	if err != nil {
		return RetryPolicy{}, err
	}
	if document.MaxAttempts > 1 && (initial <= 0 || maximum < initial || maximum > time.Hour) {
		return RetryPolicy{}, fmt.Errorf("retry backoff must be positive, ordered, and at most 1h")
	}
	return RetryPolicy{MaxAttempts: document.MaxAttempts, InitialBackoff: initial, MaxBackoff: maximum}, nil
}

func parseRequiredDuration(name, value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 0, fmt.Errorf("%s is required", name)
	}
	return parseOptionalDuration(name, value)
}

func parseOptionalDuration(name, value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid: %w", name, err)
	}
	return duration, nil
}

func validateSafeString(value string, maximum int) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maximum {
		return fmt.Errorf("value must be non-empty, trimmed, and bounded")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("value contains control characters")
		}
	}
	return nil
}
