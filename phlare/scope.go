package phlare

import (
	"github.com/mr-pmillz/gophlare/utils"
	"reflect"
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

// NewScope initializes a Scope object using the provided Options, parsing and validating various input configurations.
// Returns the constructed Scope and an error if any issues occur during initialization.
// nolint:gocognit
func NewScope(opts *Options) (*Scope, error) {
	scope := new(Scope)
	outOfScopeType := reflect.TypeOf(opts.OutOfScope)
	if outOfScopeType == nil {
		scope.OutOfScope = make([]string, 0)
	} else {
		switch outOfScopeType.Kind() {
		case reflect.Slice:
			scope.OutOfScope = append(scope.OutOfScope, opts.OutOfScope.([]string)...)
		case reflect.String:
			if opts.OutOfScope.(string) != "" {
				if exists, err := utils.Exists(opts.OutOfScope.(string)); exists && err == nil {
					outOfScopes, err := utils.ReadLines(opts.OutOfScope.(string))
					if err != nil {
						return nil, err
					}
					scope.OutOfScope = append(scope.OutOfScope, outOfScopes...)
				} else {
					scope.OutOfScope = append(scope.OutOfScope, opts.OutOfScope.(string))
				}
			}
		default:
			// Do Nothing
		}
	}

	// check if domain arg is file, string, or a slice
	rtd := reflect.TypeOf(opts.Domain)
	if rtd == nil {
		scope.Domains = make([]string, 0)
	} else {
		switch rtd.Kind() {
		case reflect.Slice:
			for _, domain := range opts.Domain.([]string) {
				scope.addDomains(domain)
			}
		case reflect.String:
			if isFile, err := utils.Exists(opts.Domain.(string)); isFile && err == nil {
				domainList, err := utils.ReadLines(opts.Domain.(string))
				if err != nil {
					return nil, err
				}

				// parse --domain file or string into scope object
				for _, domain := range domainList {
					scope.addDomains(domain)
				}
			} else {
				scope.addDomains(opts.Domain.(string))
			}
		default:
			// Do Nothing
		}
	}

	// check if emails arg is file, string, or a slice
	rte := reflect.TypeOf(opts.Emails)
	if rte == nil {
		scope.Emails = make([]string, 0)
	} else {
		switch rte.Kind() {
		case reflect.Slice:
			scope.Emails = append(scope.Emails, opts.Emails.([]string)...)
		case reflect.String:
			if isFile, err := utils.Exists(opts.Emails.(string)); isFile && err == nil {
				emailList, err := utils.ReadLines(opts.Emails.(string))
				if err != nil {
					return nil, err
				}
				scope.Emails = append(scope.Emails, emailList...)
			} else {
				scope.Emails = append(scope.Emails, opts.Emails.(string))
			}
		default:
			// Do Nothing
		}
	}

	// check if files-to-download arg is file, string, or a slice
	rtf := reflect.TypeOf(opts.FilesToDownload)
	if rtf == nil {
		scope.FilesToDownload = make([]string, 0)
	} else {
		switch rtf.Kind() {
		case reflect.Slice:
			scope.FilesToDownload = append(scope.FilesToDownload, opts.FilesToDownload.([]string)...)
		case reflect.String:
			if isFile, err := utils.Exists(opts.FilesToDownload.(string)); isFile && err == nil {
				filesToDownload, err := utils.ReadLines(opts.FilesToDownload.(string))
				if err != nil {
					return nil, err
				}
				scope.FilesToDownload = append(scope.FilesToDownload, filesToDownload...)
			} else {
				scope.FilesToDownload = append(scope.FilesToDownload, opts.FilesToDownload.(string))
			}
		default:
			// Do Nothing
		}
	}

	rtUIDF := reflect.TypeOf(opts.UserIDFormat)
	if rtUIDF == nil {
		scope.UserIDFormats = make([]string, 0)
	} else {
		switch rtUIDF.Kind() {
		case reflect.Slice:
			scope.UserIDFormats = append(scope.UserIDFormats, opts.UserIDFormat.([]string)...)
		case reflect.String:
			if isFile, err := utils.Exists(opts.UserIDFormat.(string)); isFile && err == nil {
				userIDFormats, err := utils.ReadLines(opts.UserIDFormat.(string))
				if err != nil {
					return nil, err
				}
				scope.UserIDFormats = append(scope.UserIDFormats, userIDFormats...)
			} else {
				scope.UserIDFormats = append(scope.UserIDFormats, opts.UserIDFormat.(string))
			}
		default:
			// Do Nothing
		}
	}

	rtSev := reflect.TypeOf(opts.Severity)
	if rtSev == nil {
		scope.Severity = make([]string, 0)
	} else {
		switch rtSev.Kind() {
		case reflect.Slice:
			scope.Severity = append(scope.Severity, opts.Severity.([]string)...)
		case reflect.String:
			if isFile, err := utils.Exists(opts.Severity.(string)); isFile && err == nil {
				severity, err := utils.ReadLines(opts.Severity.(string))
				if err != nil {
					return nil, err
				}
				scope.Severity = append(scope.Severity, severity...)
			} else {
				scope.Severity = append(scope.Severity, opts.Severity.(string))
			}
		default:
			// Do Nothing
		}
	}

	rtEvents := reflect.TypeOf(opts.EventsFilterTypes)
	if rtEvents == nil {
		scope.EventsFilterTypes = make([]string, 0)
	} else {
		switch rtEvents.Kind() {
		case reflect.Slice:
			scope.EventsFilterTypes = append(scope.EventsFilterTypes, opts.EventsFilterTypes.([]string)...)
		case reflect.String:
			if isFile, err := utils.Exists(opts.EventsFilterTypes.(string)); isFile && err == nil {
				eventsFilterTypes, err := utils.ReadLines(opts.EventsFilterTypes.(string))
				if err != nil {
					return nil, err
				}
				scope.EventsFilterTypes = append(scope.EventsFilterTypes, eventsFilterTypes...)
			} else {
				scope.EventsFilterTypes = append(scope.EventsFilterTypes, opts.EventsFilterTypes.(string))
			}
		default:
			// Do Nothing
		}
	}

	return scope, nil
}

// addDomains ...
//
//nolint:gocognit
func (s *Scope) addDomains(domain string) {
	if domain != "" && !utils.ContainsExactMatch(s.OutOfScope, domain) {
		s.Domains = append(s.Domains, domain)
	}
}
