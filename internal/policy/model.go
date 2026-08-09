package policy

import (
	"crypto/sha256"
	"fmt"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/model"
)

const InputAPIVersion = "opscustodian.dev/policy-input/v1alpha1"

type Input struct {
	APIVersion string        `json:"apiVersion"`
	BOM        model.AgentBOM `json:"bom"`
	Drift      *drift.Report `json:"drift,omitempty"`
}

type Decision struct {
	Deny []Message `json:"deny"`
	Warn []Message `json:"warn"`
}

type Message struct {
	ID          string   `json:"id,omitempty"`
	Rule        string   `json:"rule"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	Severity    string   `json:"severity"`
	AgentID     string   `json:"agentId,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	EvidenceIDs []string `json:"evidenceIds,omitempty"`
}

func (decision *Decision) Normalize() {
	for index := range decision.Deny {
		normalizeMessage(&decision.Deny[index], "high")
	}
	for index := range decision.Warn {
		normalizeMessage(&decision.Warn[index], "medium")
	}
}

func normalizeMessage(message *Message, defaultSeverity string) {
	if message.Severity == "" {
		message.Severity = defaultSeverity
	}
	if message.ID == "" {
		value := message.Rule + "\x00" + message.AgentID + "\x00" + message.Title + "\x00" + message.Message
		sum := sha256.Sum256([]byte(value))
		message.ID = fmt.Sprintf("policy-%x", sum[:6])
	}
}

func (decision Decision) Validate() error {
	if decision.Deny == nil || decision.Warn == nil {
		return fmt.Errorf("decision must contain deny and warn arrays")
	}
	for _, group := range []struct {
		name     string
		messages []Message
	}{{"deny", decision.Deny}, {"warn", decision.Warn}} {
		for index, message := range group.messages {
			if message.Rule == "" || message.Title == "" || message.Message == "" {
				return fmt.Errorf("%s[%d] must contain rule, title, and message", group.name, index)
			}
			if !validSeverity(message.Severity) {
				return fmt.Errorf("%s[%d] has unsupported severity %q", group.name, index, message.Severity)
			}
		}
	}
	return nil
}

func validSeverity(value string) bool {
	switch value {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}
