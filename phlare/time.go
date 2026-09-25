package phlare

import (
	"time"

	"github.com/mr-pmillz/gophlare/flareapi/flaretime"
)

// FlareTime is the timestamp type used by every Flare API model. It aliases
// flaretime.Time so the generated models in flareapi and gophlare's own code
// share one type that decodes the API's mixed timestamp formats and
// implements json.Unmarshaler, driver.Valuer, and sql.Scanner.
type FlareTime = flaretime.Time

// EpochToTime converts an epoch timestamp (in seconds) to a *time.Time value.
// It returns a pointer to the corresponding time in the UTC timezone.
func EpochToTime(epoch int64) *time.Time {
	t := time.Unix(epoch, 0).UTC()
	return &t
}
