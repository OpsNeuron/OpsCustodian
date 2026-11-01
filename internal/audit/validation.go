package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	maxEventBytes = 64 << 10
	maxFieldBytes = 200
)

var eventIDPattern = regexp.MustCompile(`^audit-[0-9a-f]{32}$`)

// ValidateEvent enforces the shared audit envelope before any sink observes it.
func ValidateEvent(event Event) error {
	if event.SchemaVersion != SchemaVersion || !eventIDPattern.MatchString(event.EventID) || !validAuditField(event.EventName) {
		return fmt.Errorf("audit event contract is invalid")
	}
	if event.SeverityNumber < 1 || event.SeverityNumber > 24 {
		return fmt.Errorf("audit event severity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		return fmt.Errorf("audit event timestamp is invalid")
	}
	if !validAuditField(event.InstrumentationScope.Name) || len(event.Resource) == 0 {
		return fmt.Errorf("audit event resource or instrumentation scope is invalid")
	}
	if err := validateFlatFields("resource", event.Resource); err != nil {
		return err
	}
	if err := validateFlatFields("attribute", event.Attributes); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > maxEventBytes {
		return fmt.Errorf("audit event payload is invalid or exceeds 64 KiB")
	}
	return nil
}

func validateFlatFields(kind string, fields map[string]any) error {
	for key, value := range fields {
		if !validAuditField(key) || !validAuditValue(value) {
			return fmt.Errorf("audit event %s %q is invalid", kind, key)
		}
	}
	return nil
}

func validAuditField(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxFieldBytes && !strings.ContainsAny(value, "\x00\r\n")
}

func validAuditValue(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	case reflect.Float32, reflect.Float64:
		floating := reflected.Float()
		return !math.IsNaN(floating) && !math.IsInf(floating, 0)
	case reflect.Array, reflect.Slice:
		for index := 0; index < reflected.Len(); index++ {
			item := reflected.Index(index)
			if item.Kind() == reflect.Interface {
				item = item.Elem()
			}
			if !item.IsValid() || item.Kind() == reflect.Array || item.Kind() == reflect.Slice || item.Kind() == reflect.Map || item.Kind() == reflect.Struct || item.Kind() == reflect.Pointer || !validAuditValue(item.Interface()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
