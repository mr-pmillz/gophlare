package utils

import (
	"sort"
	"strconv"
	"strings"
)

// ContainsPrefix checks if a string exists within a slice
func ContainsPrefix(s []string, str string) bool {
	for _, v := range s {
		if strings.HasPrefix(str, v) {
			return true
		}
	}

	return false
}

// SortUnique ...
func SortUnique(slice []string) []string {
	unique := RemoveDuplicateStr(slice)
	sort.Sort(StringSlice(unique))
	return unique
}

func Less(a, b string) bool {
	for {
		if p := commonPrefix(a, b); p != 0 {
			a = a[p:]
			b = b[p:]
		}
		if len(a) == 0 {
			return len(b) != 0
		}
		if ia := digits(a); ia > 0 {
			if ib := digits(b); ib > 0 {
				// Both sides have digits.
				an, aerr := strconv.ParseUint(a[:ia], 10, 64)
				bn, berr := strconv.ParseUint(b[:ib], 10, 64)
				if aerr == nil && berr == nil {
					if an != bn {
						return an < bn
					}
					// Semantically the same digits, e.g. "00" == "0", "01" == "1". In
					// this case, only continue processing if there's trailing data on
					// both sides, otherwise do lexical comparison.
					if ia != len(a) && ib != len(b) {
						a = a[ia:]
						b = b[ib:]
						continue
					}
				}
			}
		}
		return a < b
	}
}

// StringSlice attaches the methods of Interface to []string, sorting in
// increasing order using natural order.
type StringSlice []string

func (p StringSlice) Len() int           { return len(p) }
func (p StringSlice) Less(i, j int) bool { return Less(p[i], p[j]) }
func (p StringSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// commonPrefix returns the common prefix except for digits.
func commonPrefix(a, b string) int {
	m := len(a)
	if n := len(b); n < m {
		m = n
	}
	if m == 0 {
		return 0
	}
	_ = a[m-1]
	_ = b[m-1]
	for i := 0; i < m; i++ {
		ca := a[i]
		cb := b[i]
		if (ca >= '0' && ca <= '9') || (cb >= '0' && cb <= '9') || ca != cb {
			return i
		}
	}
	return m
}

func digits(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return i
		}
	}
	return len(s)
}
