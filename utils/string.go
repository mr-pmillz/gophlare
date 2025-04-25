package utils

import (
	"fmt"
	valid "github.com/asaskevich/govalidator"
	"net/url"
	"regexp"
	"strings"
	"time"
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
		`^[A-Za-z]{1,3}\d{1,6}$`,                   // Simple format: up to 3 letters followed by up to 6 numbers
		`^[A-Za-z]+\\[A-Za-z]+\d+$`,        // Domain\Username format with letter(s) followed by number(s)
		`^[A-Za-z]+\\[A-Za-z0-9]+$`,        // Domain\Username format with alphanumeric username
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
			if !ContainsExactMatch(AlphaTLDs, domainParts[i]) {
				break
			}
			tldCount++
		}

		// Handle special cases like .co.uk
		if tldCount > 1 && numParts > tldCount+1 {
			// Check if the part before the TLD is also in AlphaTLDs
			if ContainsExactMatch(AlphaTLDs, domainParts[numParts-tldCount-1]) {
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
