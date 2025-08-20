package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	valid "github.com/asaskevich/govalidator"
)

// FormatDate Accepts multiple input formats: MM-DD-YYYY, YYYY-MM-DD, MM/DD/YYYY, YYYY/MM/DD
// Always returns the date in time.RFC3339 (YYYY-MM-DDT00:00:00Z)
func FormatDate(date string) (string, error) {
	// Define possible date formats
	formats := []string{
		"01-02-2006", // MM-DD-YYYY
		"2006-01-02", // YYYY-MM-DD
		"01/02/2006", // MM/DD/YYYY
		"2006/01/02", // YYYY/MM/DD
	}

	var parsedTime time.Time
	var err error

	// Try parsing using each format
	for _, layout := range formats {
		parsedTime, err = time.Parse(layout, date)
		if err == nil {
			return parsedTime.Format(time.RFC3339), nil // Return in RFC3339 format
		}
	}

	return "", fmt.Errorf("invalid date format: %s", date)
}

// EpochOrDateToTime converts an interface{} epoch timestamp (seconds since Unix epoch) to time.Time in UTC
func EpochOrDateToTime(epoch interface{}) (time.Time, error) {
	switch v := epoch.(type) {
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case string:
		return time.Parse(time.RFC3339, v)
	case time.Time:
		return v.UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("invalid epoch type: %T", epoch)
	}
}

// FindMostRecentEpoch returns the most recent (latest) epoch from a slice of epochs
// relative to the current time. If all epochs are in the future, returns the closest one.
func FindMostRecentEpoch(epochs []interface{}) (interface{}, error) {
	if len(epochs) == 0 {
		return nil, fmt.Errorf("epochs slice cannot be empty")
	}

	now := time.Now().UTC()
	var mostRecentEpoch interface{}
	var mostRecentTime time.Time
	var found bool

	// First pass: look for the most recent past epoch
	for _, epoch := range epochs {
		epochTime, err := EpochOrDateToTime(epoch)
		if err != nil {
			continue
		}

		// If it's in the past and more recent than our current best
		if epochTime.Before(now) && (!found || epochTime.After(mostRecentTime)) {
			mostRecentEpoch = epoch
			mostRecentTime = epochTime
			found = true
		}
	}

	// If we found a past epoch, return it
	if found {
		return mostRecentEpoch, nil
	}

	// If all epochs are in the future, find the closest one
	var closestEpoch interface{}
	var smallestDiff time.Duration
	found = false

	for _, epoch := range epochs {
		epochTime, err := EpochOrDateToTime(epoch)
		if err != nil {
			continue
		}

		diff := epochTime.Sub(now)
		if !found || diff < smallestDiff {
			closestEpoch = epoch
			smallestDiff = diff
			found = true
		}
	}

	if !found {
		return nil, fmt.Errorf("no valid epochs found in the slice")
	}

	return closestEpoch, nil
}

// EpochToFloat64 ...
func EpochToFloat64(epoch interface{}) (float64, error) {
	switch v := epoch.(type) {
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case time.Time:
		return float64(v.UTC().Unix()), nil
	case string:
		// Try to parse string as int64 first
		if intVal, err := strconv.ParseInt(v, 10, 64); err == nil {
			return float64(intVal), nil
		}
		// If that fails, try to parse as float64
		if floatVal, err := strconv.ParseFloat(v, 64); err == nil {
			return floatVal, nil
		}
		return 0, fmt.Errorf("unable to parse string '%s' as numeric value", v)
	case nil:
		return 0, fmt.Errorf("epoch cannot be nil")
	default:
		return 0, fmt.Errorf("unsupported type: %T", v)
	}
}

// CompareBreachedAtToPasswordLastSetDate compares if the breachedAt date is after the passwordLastSet date
// returns true if breachedAt is after passwordLastSet, false otherwise
// returns the difference between breachedAt and passwordLastSet in string format
// returns an error if the input is not a valid time.Time or epoch timestamp
func CompareBreachedAtToPasswordLastSetDate(breachedAt, passwordLastSet interface{}) (bool, string, error) {
	pwLastSetTime, err := EpochOrDateToTime(passwordLastSet)
	if err != nil {
		return false, "", err
	}

	breachedAtTime, err := EpochOrDateToTime(breachedAt)
	if err != nil {
		return false, "", err
	}
	if pwLastSetTime.IsZero() || breachedAtTime.IsZero() {
		return false, "", nil
	}
	isAfter := breachedAtTime.After(pwLastSetTime)
	diff := breachedAtTime.Sub(pwLastSetTime)

	// Convert duration to total seconds
	totalSeconds := int64(diff.Seconds())

	// Calculate time components
	years := totalSeconds / 31536000 // seconds in a year (365 days)
	remainingAfterYears := totalSeconds % 31536000
	months := remainingAfterYears / 2592000 // seconds in a month (30 days)
	remainingAfterMonths := remainingAfterYears % 2592000
	days := remainingAfterMonths / 86400 // seconds in a day

	// Format diff to human-readable duration format
	pwLastSetSinceBreach := fmt.Sprintf("%d years, %d months, %d days", years, months, days)

	return isAfter, pwLastSetSinceBreach, nil
}

// IsHash checks if the input string matches the format of common hash algorithm formats.
// hopefully a temporary work-around since flare does not distinguish by credential type and groups hashes and cleartext passwords into the same hash key.
// this is to reduce non cleartext password results noise that can muddy up the cred stuffing auto generated lists...
func IsHash(input string) bool {
	// Normalize input by trimming whitespace and converting to lowercase
	input = strings.TrimSpace(strings.ToLower(input))

	// Define regex patterns for hash formats
	hashPatterns := map[string]string{
		"MD5":       "^[a-f0-9]{32}$",
		"SHA-1":     "^[a-f0-9]{40}$",
		"TIGER-192": "^[a-f0-9]{48}$",
		"SHA-3-224": "^[a-f0-9]{56}$",
		"SHA-256":   "^[a-f0-9]{64}$",
		"SHA-384":   "^[a-f0-9]{96}$",
		"SHA-512":   "^[a-f0-9]{128}$",
		"Blowfish":  `^\$2[aby]?\$\d{1,2}\$[./a-zA-Z0-9]{53}$`, // Blowfish ($2a$, $2b$, $2y$)
	}

	// Check the input against each pattern
	for _, pattern := range hashPatterns {
		match, _ := regexp.MatchString(pattern, input)
		if match {
			return true
		}
	}

	// additional checks for sampled hash values
	if ContainsPrefix([]string{"pbkdf2_sha256", "pbkdf2_sha512", "c2NyeXB0AA4AAAAIAAAA", "$S$D", "$P$B", "sha1$2", "sha1$4"}, input) && len(input) >= 32 {
		return true
	}

	return false
}

// IsLikelyAnEncryptedValue checks if the given input string is likely an encrypted value by evaluating its format.
func IsLikelyAnEncryptedValue(input string) bool {
	// Normalize input by trimming whitespace and converting to lowercase
	input = strings.TrimSpace(strings.ToLower(input))
	if strings.HasSuffix(input, "=") && valid.IsBase64(input) {
		// likely an encrypted value that flare includes in the Items[n].Hash key...
		return true
	}

	return false
}

// IsUserIDFormatMatch ...
func IsUserIDFormatMatch(credentialUsername, userIDFormat string) bool {
	// Dynamically generate a regex pattern to match the userIDFormat
	patternStr := "^"
	for _, char := range userIDFormat {
		switch {
		case char >= '0' && char <= '9':
			patternStr += "\\d"
		case (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z'):
			patternStr += "[a-zA-Z]"
		default:
			patternStr += regexp.QuoteMeta(string(char))
		}
	}
	patternStr += "$"

	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		return false
	}
	return pattern.MatchString(credentialUsername)
}

// IsUserID checks if a string matches common user ID patterns
// It matches formats like:
// - A12345 (letter followed by numbers)
// - ABC1234 (multiple letters followed by numbers)
// - AA\A12345 (domain\username format)
// - DOMAIN\user123 (domain\username with mixed case)
func IsUserID(username string) bool {
	// Define regex patterns for different user ID formats
	patterns := []string{
		`^[A-Za-z]{1,3}\d{1,6}$`,    // Simple format: up to 3 letters followed by up to 6 numbers
		`^[A-Za-z]+\\[A-Za-z]+\d+$`, // Domain\Username format with letter(s) followed by number(s)
		`^[A-Za-z]+\\[A-Za-z0-9]+$`, // Domain\Username format with alphanumeric username
	}

	// Check username against each pattern
	for _, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, username)
		if err == nil && matched {
			return true
		}
	}

	return false
}

// RemoveDuplicateStr removes duplicate strings from a slice of strings
func RemoveDuplicateStr(strSlice []string) []string { //nolint:typecheck
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

var nonAlphanumericAndSpaceRegex = regexp.MustCompile(`[^a-zA-Z0-9]+|\s+`)

// SanitizeString ...
func SanitizeString(str string) string {
	str = strings.ReplaceAll(str, "'", "")
	// replace multiple non-alphanumeric characters with a single underscore
	str = nonAlphanumericAndSpaceRegex.ReplaceAllString(str, "_")

	// Remove underscores at the beginning and end of the filename
	str = strings.Trim(str, "_")

	// Limit the filename length to prevent extremely long filenames
	if len(str) > 255 {
		str = str[:255]
	}

	return str
}

// ContainsExactMatch checks if a string exists within a slice
func ContainsExactMatch(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// ContainsExactMatchLowercase checks if a string exists within a slice
func ContainsExactMatchLowercase(s []string, str string) bool {
	for _, v := range s {
		if v == strings.ToLower(str) {
			return true
		}
	}

	return false
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// ExtractBaseDomain extracts the base domain from a given URL or DNS name
func ExtractBaseDomain(target string) (string, error) {
	switch {
	case isURL(target):
		parsedURL, err := url.Parse(target)
		if err != nil {
			return "", LogError(err)
		}
		target = parsedURL.Hostname()
		fallthrough
	case valid.IsDNSName(target):
		if valid.IsIP(target) {
			return "", nil
		}
		domainParts := strings.Split(target, ".")
		numParts := len(domainParts)

		// Start from the end and find the first non-TLD part
		tldCount := 0
		for i := numParts - 1; i >= 0; i-- {
			if !ContainsExactMatchLowercase(AlphaTLDs, domainParts[i]) {
				break
			}
			tldCount++
		}

		// Handle special cases like .co.uk
		if tldCount > 1 && numParts > tldCount+1 {
			// Check if the part before the TLD is also in AlphaTLDs
			if ContainsExactMatchLowercase(AlphaTLDs, domainParts[numParts-tldCount-1]) {
				tldCount++
			}
		}

		// If we have more parts than just the TLD, return the last non-TLD part and all TLD parts
		if numParts > tldCount {
			return strings.Join(domainParts[numParts-tldCount-1:], "."), nil
		} else {
			return strings.Join(domainParts, "."), nil
		}
	case valid.IsIP(target):
		return "", nil
	}
	return "", nil
}

// HasBaseDomainWithoutTLDPrefix ...
func HasBaseDomainWithoutTLDPrefix(credentialUsername, domain string) bool {
	baseDomain, err := ExtractBaseDomain(domain)
	if err != nil {
		return false
	}
	domainParts := strings.Split(baseDomain, ".")
	if len(domainParts) < 2 {
		return false
	}
	baseDomainNoTLD := domainParts[0]
	return strings.HasPrefix(strings.ToLower(credentialUsername), strings.ToLower(baseDomainNoTLD))
}

//// BuildStrictRegex ...
// func BuildStrictRegex(s string) (string, error) {
//	matches := regexp.MustCompile(`(?i)^([a-z]+)(\d+)$`).FindStringSubmatch(s)
//	if matches == nil {
//		return "", fmt.Errorf("input must be letter(s) followed by digits, like 'abc123456'")
//	}
//
//	prefix := strings.ToLower(matches[1])
//	digitCount := len(matches[2])
//
//	// Escape the prefix in case it contains any special regex characters
//	escapedPrefix := regexp.QuoteMeta(prefix)
//
//	// Build strict pattern: word-boundary-like match
//	pattern := fmt.Sprintf(`(?i)(^|[^a-zA-Z0-9])%s[0-9]{%d}([^a-zA-Z0-9]|$)`, escapedPrefix, digitCount)
//	return pattern, nil
// }
