package phlare

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

// UnmarshalJSON is a custom time.Time unmarshaller that supports additional time stamp formats...
func (ft *FlareTime) UnmarshalJSON(b []byte) error {
	// Remove quotes
	s := strings.Trim(string(b), "\"")
	if s == "null" || s == "" {
		*ft = FlareTime{}
		return nil
	}

	// Try multiple time formats
	formats := []string{
		"2006-01-02T15:04:05Z07:00",        // Standard RFC3339
		"2006-01-02T15:04:05",              // Without timezone
		"2006-01-02T15:04:05Z",             // With Z but no offset
		"2024-04-30T07:09:59+00:00",        // Without Z and +00:00
		"2006-01-02T15:04:05.000000",       // Fractional seconds, no timezone (naive)
		"2025-02-24T02:49:48.997342+00:00", // ISO 8601 format
		time.RFC3339Nano,                   // "2006-01-02T15:04:05.999999999Z07:00" — handles fractional seconds + timezone
		time.RFC3339,                       // "2006-01-02T15:04:05Z07:00" — no fractional seconds
		// Add more formats as needed
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			*ft = FlareTime{t}
			return nil
		}
	}

	// If all parsing attempts fail
	return fmt.Errorf("cannot parse time: %s", s)
}

// EpochToTime converts an epoch timestamp (in seconds) to a *time.Time value.
// It returns a pointer to the corresponding time in the UTC timezone.
func EpochToTime(epoch int64) *time.Time {
	t := time.Unix(epoch, 0).UTC()
	return &t
}

// Value implements the driver.Valuer interface for database serialization.
// It returns the underlying time.Time value for storage in the database.
func (ft *FlareTime) Value() (driver.Value, error) {
	if ft == nil || ft.IsZero() {
		return nil, nil
	}
	return ft.Time, nil
}

// Scan implements the sql.Scanner interface for database deserialization.
// It reads a time.Time value from the database and stores it in FlareTime.
func (ft *FlareTime) Scan(value interface{}) error {
	if value == nil {
		*ft = FlareTime{}
		return nil
	}

	switch v := value.(type) {
	case time.Time:
		*ft = FlareTime{v}
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into FlareTime", value)
	}
}
