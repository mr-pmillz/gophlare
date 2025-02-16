package utils

import (
	"regexp"
	"strings"
)

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
