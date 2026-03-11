package phlare

import (
	"reflect"
	"testing"
)

func TestNewScope(t *testing.T) {
	tests := []struct {
		name              string
		opts              *Options
		wantDomains       []string
		wantEmails        []string
		wantUserIDFormats []string
		wantFilesToDL     []string
		wantOutOfScope    []string
		wantSeverity      []string
		wantEventsFilter  []string
	}{
		{
			name:              "all nil fields produce empty slices",
			opts:              &Options{},
			wantDomains:       []string{},
			wantEmails:        []string{},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{},
			wantEventsFilter:  []string{},
		},
		{
			name: "string values become single-element slices",
			opts: &Options{
				Domains:  "example.com",
				Emails:   "user@test.com",
				Severity: "high",
			},
			wantDomains:       []string{"example.com"},
			wantEmails:        []string{"user@test.com"},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{"high"},
			wantEventsFilter:  []string{},
		},
		{
			name: "slice values passed through",
			opts: &Options{
				Domains:  []string{"example.com", "test.com"},
				Emails:   []string{"a@b.com", "c@d.com"},
				Severity: []string{"high", "critical"},
			},
			wantDomains:       []string{"example.com", "test.com"},
			wantEmails:        []string{"a@b.com", "c@d.com"},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{"high", "critical"},
			wantEventsFilter:  []string{},
		},
		{
			name: "empty string values produce empty slices",
			opts: &Options{
				Domains: "",
				Emails:  "",
			},
			wantDomains:       []string{},
			wantEmails:        []string{},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{},
			wantEventsFilter:  []string{},
		},
		{
			name: "out-of-scope filtering removes matching domains",
			opts: &Options{
				OutOfScope: []string{"excluded.com"},
				Domains:    []string{"example.com", "excluded.com", "test.com"},
			},
			wantDomains:       []string{"example.com", "test.com"},
			wantEmails:        []string{},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{"excluded.com"},
			wantSeverity:      []string{},
			wantEventsFilter:  []string{},
		},
		{
			name: "out-of-scope as string filters domain",
			opts: &Options{
				OutOfScope: "excluded.com",
				Domains:    []string{"example.com", "excluded.com"},
			},
			wantDomains:       []string{"example.com"},
			wantEmails:        []string{},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{"excluded.com"},
			wantSeverity:      []string{},
			wantEventsFilter:  []string{},
		},
		{
			name: "all fields populated with slices",
			opts: &Options{
				Domains:           []string{"example.com"},
				Emails:            []string{"user@test.com"},
				UserIDFormat:      []string{"a12345"},
				FilesToDownload:   []string{"passwords.txt"},
				OutOfScope:        []string{"bad.com"},
				Severity:          []string{"high", "critical"},
				EventsFilterTypes: []string{"stealer_log", "leak"},
			},
			wantDomains:       []string{"example.com"},
			wantEmails:        []string{"user@test.com"},
			wantUserIDFormats: []string{"a12345"},
			wantFilesToDL:     []string{"passwords.txt"},
			wantOutOfScope:    []string{"bad.com"},
			wantSeverity:      []string{"high", "critical"},
			wantEventsFilter:  []string{"stealer_log", "leak"},
		},
		{
			name: "mixed types - some string some slice some nil",
			opts: &Options{
				Domains:           []string{"example.com", "test.com"},
				Emails:            "single@email.com",
				Severity:          []string{"medium", "high"},
				EventsFilterTypes: "stealer_log",
			},
			wantDomains:       []string{"example.com", "test.com"},
			wantEmails:        []string{"single@email.com"},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{"medium", "high"},
			wantEventsFilter:  []string{"stealer_log"},
		},
		{
			name: "empty domain strings filtered out by addDomains",
			opts: &Options{
				Domains: []string{"example.com", "", "test.com", ""},
			},
			wantDomains:       []string{"example.com", "test.com"},
			wantEmails:        []string{},
			wantUserIDFormats: []string{},
			wantFilesToDL:     []string{},
			wantOutOfScope:    []string{},
			wantSeverity:      []string{},
			wantEventsFilter:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, err := NewScope(tt.opts)
			if err != nil {
				t.Fatalf("NewScope() unexpected error = %v", err)
			}

			if !reflect.DeepEqual(scope.Domains, tt.wantDomains) {
				t.Errorf("Domains = %v, want %v", scope.Domains, tt.wantDomains)
			}
			if !reflect.DeepEqual(scope.Emails, tt.wantEmails) {
				t.Errorf("Emails = %v, want %v", scope.Emails, tt.wantEmails)
			}
			if !reflect.DeepEqual(scope.UserIDFormats, tt.wantUserIDFormats) {
				t.Errorf("UserIDFormats = %v, want %v", scope.UserIDFormats, tt.wantUserIDFormats)
			}
			if !reflect.DeepEqual(scope.FilesToDownload, tt.wantFilesToDL) {
				t.Errorf("FilesToDownload = %v, want %v", scope.FilesToDownload, tt.wantFilesToDL)
			}
			if !reflect.DeepEqual(scope.OutOfScope, tt.wantOutOfScope) {
				t.Errorf("OutOfScope = %v, want %v", scope.OutOfScope, tt.wantOutOfScope)
			}
			if !reflect.DeepEqual(scope.Severity, tt.wantSeverity) {
				t.Errorf("Severity = %v, want %v", scope.Severity, tt.wantSeverity)
			}
			if !reflect.DeepEqual(scope.EventsFilterTypes, tt.wantEventsFilter) {
				t.Errorf("EventsFilterTypes = %v, want %v", scope.EventsFilterTypes, tt.wantEventsFilter)
			}
		})
	}
}

func TestResolveToSlice(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want []string
	}{
		{"nil returns empty slice", nil, []string{}},
		{"empty string returns empty slice", "", []string{}},
		{"non-empty string returns single-element slice", "hello", []string{"hello"}},
		{"string slice passed through", []string{"a", "b"}, []string{"a", "b"}},
		{"empty string slice passed through", []string{}, []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveToSlice(tt.val)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("resolveToSlice(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}
