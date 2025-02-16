package utils

import (
	"testing"
)

func TestContainsPrefix(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		str      string
		expected bool
	}{
		{
			name:     "slice contains single matching prefix",
			slice:    []string{"go", "test", "utils"},
			str:      "golang",
			expected: true,
		},
		{
			name:     "slice contains multiple prefixes, one matches",
			slice:    []string{"prefix", "go", "test"},
			str:      "gopher",
			expected: true,
		},
		{
			name:     "slice contains no matching prefix",
			slice:    []string{"random", "strings", "here"},
			str:      "golang",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			str:      "tested",
			expected: false,
		},
		{
			name:     "empty string, non-empty slice",
			slice:    []string{"test", "prefix"},
			str:      "",
			expected: false,
		},
		{
			name:     "empty string, empty slice",
			slice:    []string{},
			str:      "",
			expected: false,
		},
		{
			name:     "exact match with one prefix",
			slice:    []string{"gopher"},
			str:      "gopher",
			expected: true,
		},
		{
			name:     "string contains prefix as substring but not at start",
			slice:    []string{"go", "test"},
			str:      "goliveinpeace",
			expected: true,
		},
		{
			name:     "case sensitivity mismatch",
			slice:    []string{"Go", "test"},
			str:      "golang",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsPrefix(tt.slice, tt.str)
			if result != tt.expected {
				t.Errorf("ContainsPrefix(%v, %q) = %v; want %v", tt.slice, tt.str, result, tt.expected)
			}
		})
	}
}

func TestSortUnique(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates, already sorted",
			input:    []string{"apple", "banana", "cherry"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "contains duplicates",
			input:    []string{"banana", "banana", "apple", "apple", "cherry"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "unsorted unique elements",
			input:    []string{"cherry", "banana", "apple"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "mix of upper and lower case",
			input:    []string{"Apple", "apple", "Banana", "banana"},
			expected: []string{"Apple", "Banana", "apple", "banana"},
		},
		{
			name:     "numeric strings",
			input:    []string{"10", "2", "1", "2", "10", "20"},
			expected: []string{"1", "2", "10", "20"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SortUnique(tt.input)
			if !equalSlices(result, tt.expected) {
				t.Errorf("SortUnique(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
