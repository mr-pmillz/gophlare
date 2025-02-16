package phlare

import (
	"github.com/mr-pmillz/gophlare/utils"
	"reflect"
)

type Scope struct {
	Domains         []string
	Emails          []string
	FilesToDownload []string
	OutOfScope      []string
	SubDomains      []string
}

// NewScope ...
//
//nolint:gocognit
func NewScope(opts *Options) (*Scope, error) {
	scope := new(Scope)
	outOfScopeType := reflect.TypeOf(opts.OutOfScope)
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

	// check if domain arg is file, string, or a slice
	rtd := reflect.TypeOf(opts.Domain)
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

	// check if emails arg is file, string, or a slice
	rte := reflect.TypeOf(opts.Emails)
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

	// check if files-to-download arg is file, string, or a slice
	rtf := reflect.TypeOf(opts.FilesToDownload)
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
