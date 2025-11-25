package phlare

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// createTestCommand creates a cobra command with all flags configured
// similar to what ConfigureCommand does, for testing purposes
func createTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
	}
	// Set a root command with version for the test
	root := &cobra.Command{
		Use:     "root",
		Version: "1.0.0-test",
	}
	root.AddCommand(cmd)

	// strings - use Flags() instead of PersistentFlags() for direct testing
	cmd.Flags().StringP("company", "c", "", "company name that your testing")
	cmd.Flags().StringP("query", "q", "", "query to use for searching stealer logs.")
	cmd.Flags().StringP("output", "o", "", "report output dir")
	cmd.Flags().StringP("user-agent", "", "", "custom user-agent to use for requests")
	cmd.Flags().StringP("from", "f", "", "from date used for a filter for stealer log searches. ex. 2021-01-01 ")
	cmd.Flags().StringP("to", "", "", "to date used for a filter for stealer log searches. ex. 2025-01-01. Defaults to today.")
	// strings of interface type that can be a file, a slice, or a singular string
	cmd.Flags().StringP("domains", "d", "", "domain string, can be a file file containing domains ex. domains.txt, or comma-separated list of strings")
	cmd.Flags().StringP("out-of-scope", "", "", "out of scope domains, IPs, or CIDRs")
	cmd.Flags().StringP("files-to-download", "", "", "comma separated list of files to match on and download if they exist from the query")
	cmd.Flags().StringP("emails", "e", "", "emails to check in bulk. Can be a comma separated slice or a file containing emails. ex. emails.txt")
	cmd.Flags().StringP("user-id-format", "u", "", "if you know the user ID format ex. a12345 , include this to enhance matching in-scope results. can be a string, a file, or comma-separated list of strings")
	cmd.Flags().StringP("severity", "s", "", "the stealer log severities to filter on. can be a string, a file, or comma-separated list of strings")
	cmd.Flags().StringP("events-filter-types", "", "", "flare global events filter types.")
	// integers
	cmd.Flags().IntP("timeout", "", 900, "timeout duration for API requests in seconds")
	cmd.Flags().IntP("max-zip-download-limit", "m", 50, "maximum number of zip files to download from the stealer logs. Set to 0 to download all zip files.")
	// booleans
	cmd.Flags().BoolP("search-stealer-logs-by-domain", "", false, "search the stealer logs by *@email domain(s), download and parse all the matching zip files for passwords and live cookies")
	cmd.Flags().BoolP("keep-zip-files", "", false, "keep all the matching downloaded zip files from the stealer logs")
	cmd.Flags().BoolP("search-credentials-by-domain", "", false, "search for credentials by domain")
	cmd.Flags().BoolP("search-emails-in-bulk", "", false, "search list of emails for credentials.")
	cmd.Flags().BoolP("verbose", "v", false, "enable verbose output")
	cmd.Flags().BoolP("search-stealer-logs-by-host-domain", "", false, "search the stealer logs by host domain(s), download and parse all the matching zip files for passwords and live cookies")
	cmd.Flags().BoolP("search-stealer-logs-by-wildcard-host", "", false, "search the stealer logs by host wildcard domain(s), (*.example.com) download and parse all the matching zip files for passwords and live cookies")

	return cmd
}

// TestOptions_LoadFromConfig tests loading options from config file
//
//nolint:gocognit
func TestOptions_LoadFromCommand(t *testing.T) {
	// Reset viper to ensure clean state for testing
	// LoadAPIKeys() uses viper.Unmarshal which works even without a config file
	viper.Reset()

	tests := []struct {
		name      string
		setupCmd  func() *cobra.Command
		wantErr   bool
		checkOpts func(t *testing.T, opts *Options)
	}{
		{
			name: "basic flags - company and output",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("company", "Test Company")
				_ = cmd.Flags().Set("output", "/tmp/output")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Company != "Test Company" {
					t.Errorf("Company = %v, want %v", opts.Company, "Test Company")
				}
				if opts.Output != "/tmp/output" {
					t.Errorf("Output = %v, want %v", opts.Output, "/tmp/output")
				}
			},
		},
		{
			name: "boolean flags - verbose and search options",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("verbose", "true")
				_ = cmd.Flags().Set("search-stealer-logs-by-domain", "true")
				_ = cmd.Flags().Set("keep-zip-files", "true")
				_ = cmd.Flags().Set("search-credentials-by-domain", "true")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if !opts.Verbose {
					t.Error("Verbose should be true")
				}
				if !opts.SearchStealerLogsByDomain {
					t.Error("SearchStealerLogsByDomain should be true")
				}
				if !opts.KeepZipFiles {
					t.Error("KeepZipFiles should be true")
				}
				if !opts.SearchCredentialsByDomain {
					t.Error("SearchCredentialsByDomain should be true")
				}
			},
		},
		{
			name: "integer flags - timeout and max-zip-download-limit",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("timeout", "300")
				_ = cmd.Flags().Set("max-zip-download-limit", "20")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Timeout != 300 {
					t.Errorf("Timeout = %v, want %v", opts.Timeout, 300)
				}
				if opts.MaxZipFilesToDownload != 20 {
					t.Errorf("MaxZipFilesToDownload = %v, want %v", opts.MaxZipFilesToDownload, 20)
				}
			},
		},
		{
			name: "single domain string",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("domains", "example.com")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				// Domain should be stored - either as string or slice
				if opts.Domains == nil {
					t.Error("Domains should not be nil")
					return
				}
				switch v := opts.Domains.(type) {
				case string:
					if v != "example.com" {
						t.Errorf("Domains = %v, want %v", v, "example.com")
					}
				case []string:
					if len(v) != 1 || v[0] != "example.com" {
						t.Errorf("Domains = %v, want [example.com]", v)
					}
				default:
					t.Errorf("Domains has unexpected type %T", opts.Domains)
				}
			},
		},
		{
			name: "comma-separated domains",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("domains", "example.com,test.com,demo.org")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Domains == nil {
					t.Error("Domains should not be nil")
					return
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				// Accept either string or slice
				switch v := opts.Domains.(type) {
				case string:
					if v != "example.com,test.com,demo.org" {
						t.Errorf("Domains = %v, want example.com,test.com,demo.org", v)
					}
				case []string:
					expected := []string{"example.com", "test.com", "demo.org"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("Domains = %v, want %v", v, expected)
					}
				default:
					t.Errorf("Domains has unexpected type %T", opts.Domains)
				}
			},
		},
		{
			name: "email as single string",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("emails", "test@example.com")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Emails == nil {
					t.Error("Emails should not be nil")
					return
				}
				switch v := opts.Emails.(type) {
				case string:
					if v != "test@example.com" {
						t.Errorf("Emails = %v, want %v", v, "test@example.com")
					}
				case []string:
					if len(v) != 1 || v[0] != "test@example.com" {
						t.Errorf("Emails = %v, want [test@example.com]", v)
					}
				default:
					t.Errorf("Emails has unexpected type %T", opts.Emails)
				}
			},
		},
		{
			name: "comma-separated emails",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("emails", "user1@example.com,user2@test.com")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Emails == nil {
					t.Error("Emails should not be nil")
					return
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				switch v := opts.Emails.(type) {
				case string:
					if v != "user1@example.com,user2@test.com" {
						t.Errorf("Emails = %v, want user1@example.com,user2@test.com", v)
					}
				case []string:
					expected := []string{"user1@example.com", "user2@test.com"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("Emails = %v, want %v", v, expected)
					}
				default:
					t.Errorf("Emails has unexpected type %T", opts.Emails)
				}
			},
		},
		{
			name: "severity as comma-separated values",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("severity", "medium,high,critical")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Severity == nil {
					t.Error("Severity should not be nil")
					return
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				switch v := opts.Severity.(type) {
				case string:
					if v != "medium,high,critical" {
						t.Errorf("Severity = %v, want medium,high,critical", v)
					}
				case []string:
					expected := []string{"medium", "high", "critical"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("Severity = %v, want %v", v, expected)
					}
				default:
					t.Errorf("Severity has unexpected type %T", opts.Severity)
				}
			},
		},
		{
			name: "date flags - from and to",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("from", "2023-01-01")
				_ = cmd.Flags().Set("to", "2025-12-31")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				// The dates should be formatted to RFC3339 format
				if opts.From == "" {
					t.Error("From should not be empty")
				}
				if opts.To == "" {
					t.Error("To should not be empty")
				}
				// Check that dates contain the expected year
				if len(opts.From) < 10 {
					t.Errorf("From date format seems incorrect: %v", opts.From)
				}
				if len(opts.To) < 10 {
					t.Errorf("To date format seems incorrect: %v", opts.To)
				}
			},
		},
		{
			name: "query and user-agent strings",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("query", "test query string")
				_ = cmd.Flags().Set("user-agent", "CustomAgent/1.0")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Query != "test query string" {
					t.Errorf("Query = %v, want %v", opts.Query, "test query string")
				}
				if opts.UserAgent != "CustomAgent/1.0" {
					t.Errorf("UserAgent = %v, want %v", opts.UserAgent, "CustomAgent/1.0")
				}
			},
		},
		{
			name: "all search boolean flags",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("search-stealer-logs-by-host-domain", "true")
				_ = cmd.Flags().Set("search-stealer-logs-by-wildcard-host", "true")
				_ = cmd.Flags().Set("search-emails-in-bulk", "true")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if !opts.SearchStealerLogsByHostDomain {
					t.Error("SearchStealerLogsByHostDomain should be true")
				}
				if !opts.SearchStealerLogsByWildcardHost {
					t.Error("SearchStealerLogsByWildcardHost should be true")
				}
				if !opts.SearchEmailsInBulk {
					t.Error("SearchEmailsInBulk should be true")
				}
			},
		},
		{
			name: "out-of-scope as comma-separated values",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("out-of-scope", "192.168.1.0/24,10.0.0.0/8")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.OutOfScope == nil {
					t.Error("OutOfScope should not be nil")
					return
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				switch v := opts.OutOfScope.(type) {
				case string:
					if v != "192.168.1.0/24,10.0.0.0/8" {
						t.Errorf("OutOfScope = %v, want 192.168.1.0/24,10.0.0.0/8", v)
					}
				case []string:
					expected := []string{"192.168.1.0/24", "10.0.0.0/8"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("OutOfScope = %v, want %v", v, expected)
					}
				default:
					t.Errorf("OutOfScope has unexpected type %T", opts.OutOfScope)
				}
			},
		},
		{
			name: "user-id-format as single string",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("user-id-format", "a12345")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.UserIDFormat == nil {
					t.Error("UserIDFormat should not be nil")
					return
				}
				switch v := opts.UserIDFormat.(type) {
				case string:
					if v != "a12345" {
						t.Errorf("UserIDFormat = %v, want %v", v, "a12345")
					}
				case []string:
					if len(v) != 1 || v[0] != "a12345" {
						t.Errorf("UserIDFormat = %v, want [a12345]", v)
					}
				default:
					t.Errorf("UserIDFormat has unexpected type %T", opts.UserIDFormat)
				}
			},
		},
		{
			name: "files-to-download as comma-separated values",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("files-to-download", "passwords.txt,cookies.txt,autofill.txt")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.FilesToDownload == nil {
					t.Error("FilesToDownload should not be nil")
					return
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				switch v := opts.FilesToDownload.(type) {
				case string:
					if v != "passwords.txt,cookies.txt,autofill.txt" {
						t.Errorf("FilesToDownload = %v, want passwords.txt,cookies.txt,autofill.txt", v)
					}
				case []string:
					expected := []string{"passwords.txt", "cookies.txt", "autofill.txt"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("FilesToDownload = %v, want %v", v, expected)
					}
				default:
					t.Errorf("FilesToDownload has unexpected type %T", opts.FilesToDownload)
				}
			},
		},
		{
			name: "events-filter-types as comma-separated values",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("events-filter-types", "stealer_log,leak,paste")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.EventsFilterTypes == nil {
					t.Error("EventsFilterTypes should not be nil")
					return
				}
				slice, ok := opts.EventsFilterTypes.([]string)
				if !ok {
					t.Errorf("EventsFilterTypes should be []string, got %T", opts.EventsFilterTypes)
					return
				}
				expected := []string{"stealer_log", "leak", "paste"}
				if !reflect.DeepEqual(slice, expected) {
					t.Errorf("EventsFilterTypes = %v, want %v", slice, expected)
				}
			},
		},
		{
			name: "version is set from root command",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Version != "1.0.0-test" {
					t.Errorf("Version = %v, want %v", opts.Version, "1.0.0-test")
				}
			},
		},
		{
			name: "empty flags should not cause errors",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				// Don't set any flags - all should be empty/default
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				// Just verify no panic occurred and basic defaults are set
				if opts.Timeout != 900 {
					t.Errorf("Timeout should be default 900, got %v", opts.Timeout)
				}
				if opts.MaxZipFilesToDownload != 50 {
					t.Errorf("MaxZipFilesToDownload should be default 50, got %v", opts.MaxZipFilesToDownload)
				}
				if opts.Verbose != false {
					t.Error("Verbose should be false by default")
				}
			},
		},
		{
			name: "comprehensive test with multiple flag types",
			setupCmd: func() *cobra.Command {
				cmd := createTestCommand()
				_ = cmd.Flags().Set("company", "Acme Corp")
				_ = cmd.Flags().Set("domains", "acme.com,acme.org")
				_ = cmd.Flags().Set("verbose", "true")
				_ = cmd.Flags().Set("timeout", "600")
				_ = cmd.Flags().Set("max-zip-download-limit", "100")
				_ = cmd.Flags().Set("search-stealer-logs-by-domain", "true")
				_ = cmd.Flags().Set("from", "2024-01-01")
				_ = cmd.Flags().Set("to", "2024-12-31")
				return cmd
			},
			wantErr: false,
			checkOpts: func(t *testing.T, opts *Options) {
				if opts.Company != "Acme Corp" {
					t.Errorf("Company = %v, want Acme Corp", opts.Company)
				}
				// When Opts is nil initially, ConfigureFlagOpts returns string
				switch v := opts.Domains.(type) {
				case string:
					if v != "acme.com,acme.org" {
						t.Errorf("Domains = %v, want acme.com,acme.org", v)
					}
				case []string:
					expected := []string{"acme.com", "acme.org"}
					if !reflect.DeepEqual(v, expected) {
						t.Errorf("Domains = %v, want %v", v, expected)
					}
				default:
					t.Errorf("Domains has unexpected type %T", opts.Domains)
				}
				if !opts.Verbose {
					t.Error("Verbose should be true")
				}
				if opts.Timeout != 600 {
					t.Errorf("Timeout = %v, want 600", opts.Timeout)
				}
				if opts.MaxZipFilesToDownload != 100 {
					t.Errorf("MaxZipFilesToDownload = %v, want 100", opts.MaxZipFilesToDownload)
				}
				if !opts.SearchStealerLogsByDomain {
					t.Error("SearchStealerLogsByDomain should be true")
				}
				if opts.From == "" {
					t.Error("From should not be empty")
				}
				if opts.To == "" {
					t.Error("To should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			cmd := tt.setupCmd()

			err := opts.LoadFromCommand(cmd)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFromCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkOpts != nil && !tt.wantErr {
				tt.checkOpts(t, opts)
			}
		})
	}
}
