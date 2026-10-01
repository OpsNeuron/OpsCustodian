package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxEventBytes = 64 << 10

// ValidateEvent enforces the shared audit envelope before any sink observes it.
func ValidateEvent(event Event) error {
	if event.SchemaVersion != SchemaVersion || event.EventName == "" || event.EventName != strings.TrimSpace(event.EventName) || len(event.EventName) > 200 || strings.ContainsAny(event.EventName, "\x00\r\n") {
		return fmt.Errorf("audit event contract is invalid")
	}
	if event.SeverityNumber < 1 || event.SeverityNumber > 24 {
		return fmt.Errorf("audit event severity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		return fmt.Errorf("audit event timestamp is invalid")
	}
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > maxEventBytes {
		return fmt.Errorf("audit event payload is invalid or exceeds 64 KiB")
	}
	return nil
}
