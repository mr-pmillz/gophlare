package phlare

import (
	"github.com/mr-pmillz/gophlare/utils"
)

type Scope struct {
	Domains           []string
	Emails            []string
	UserIDFormats     []string
	FilesToDownload   []string
	OutOfScope        []string
	Severity          []string
	EventsFilterTypes []string
}

// resolveToSlice converts an interface{} (nil, string, or []string) into a []string.
func resolveToSlice(val interface{}) []string {
	if val == nil {
		return make([]string, 0)
	}
	switch v := val.(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
		return make([]string, 0)
	default:
		return make([]string, 0)
	}
}

// NewScope initializes a Scope object using the provided Options, parsing and validating various input configurations.
// Returns the constructed Scope and an error if any issues occur during initialization.
func NewScope(opts *Options) (*Scope, error) {
	scope := new(Scope)

	// OutOfScope must be resolved first (Domains filtering depends on it)
	scope.OutOfScope = resolveToSlice(opts.OutOfScope)

	// Domains has special out-of-scope filtering via addDomains
	for _, domain := range resolveToSlice(opts.Domains) {
		scope.addDomains(domain)
	}
	if scope.Domains == nil {
		scope.Domains = make([]string, 0)
	}

	scope.Emails = resolveToSlice(opts.Emails)
	scope.FilesToDownload = resolveToSlice(opts.FilesToDownload)
	scope.UserIDFormats = resolveToSlice(opts.UserIDFormat)
	scope.Severity = resolveToSlice(opts.Severity)
	scope.EventsFilterTypes = resolveToSlice(opts.EventsFilterTypes)

	return scope, nil
}

// addDomains adds a domain to the scope if it's not empty and not in the out-of-scope list.
func (s *Scope) addDomains(domain string) {
	if domain != "" && !utils.ContainsExactMatch(s.OutOfScope, domain) {
		s.Domains = append(s.Domains, domain)
	}
}
