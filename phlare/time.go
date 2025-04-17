package phlare

import (
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
		"2025-02-24T02:49:48.997342+00:00", // ISO 8601 format
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
