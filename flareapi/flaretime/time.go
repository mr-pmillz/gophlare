// Package flaretime provides the timestamp type shared by every Flare API
// model in gophlare. The generated models map OpenAPI `date-time` fields to
// Time because the API mixes RFC 3339 timestamps with timezone-less ones such
// as "2026-03-04T02:22:08", which time.Time cannot decode on its own.
package flaretime

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

// Time is a time.Time that decodes every timestamp format the Flare API emits.
type Time struct {
	time.Time
}

// layouts are tried in order. RFC3339Nano also accepts values without
// fractional seconds and with either a "Z" or a numeric offset.
var layouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999", // no timezone, optional fractional seconds
	"2006-01-02",                    // date only, as accepted by the CLI date flags
}

// Parse parses s using each timestamp format the Flare API is known to emit.
// Values without a timezone are interpreted as UTC.
func Parse(s string) (Time, error) {
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return Time{t}, nil
		}
	}
	return Time{}, fmt.Errorf("cannot parse time: %s", s)
}

// UnmarshalJSON decodes a JSON string timestamp. JSON null and the empty
// string decode to the zero Time.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" || s == "" {
		*t = Time{}
		return nil
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// Value implements the driver.Valuer interface for database serialization.
// The zero Time is stored as NULL.
func (t *Time) Value() (driver.Value, error) {
	if t == nil || t.IsZero() {
		return nil, nil
	}
	return t.Time, nil
}

// Scan implements the sql.Scanner interface for database deserialization.
func (t *Time) Scan(value any) error {
	if value == nil {
		*t = Time{}
		return nil
	}

	switch v := value.(type) {
	case time.Time:
		*t = Time{v}
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into flaretime.Time", value)
	}
}
