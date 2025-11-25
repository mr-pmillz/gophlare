package utils

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Helper function to create a cobra command with a string flag
func createCmdWithStringFlag(flagName, flagValue string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagName, "", "test flag")
	if flagValue != "" {
		_ = cmd.Flags().Set(flagName, flagValue)
	}
	return cmd
}

// Helper function to create a cobra command with an int flag
func createCmdWithIntFlag(flagName string, flagValue int, setFlag bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Int(flagName, 0, "test flag")
	if setFlag {
		_ = cmd.Flags().Set(flagName, strconv.Itoa(flagValue))
	}
	return cmd
}

// Helper function to create a cobra command with a bool flag
func createCmdWithBoolFlag(flagName string, flagValue bool, setFlag bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool(flagName, false, "test flag")
	if setFlag {
		if flagValue {
			_ = cmd.Flags().Set(flagName, "true")
		} else {
			_ = cmd.Flags().Set(flagName, "false")
		}
	}
	return cmd
}

func TestConfigureFlagOpts(t *testing.T) {
	// Reset viper before tests
	viper.Reset()

	tests := []struct {
		name               string
		setupCmd           func() *cobra.Command
		lfcOpts            *LoadFromCommandOpts
		want               interface{}
		wantErr            bool
		checkNoSlashPrefix bool // special check to ensure no leading slash
	}{
		// ==========================================
		// IsFilePath=true with domain name tests
		// ==========================================
		{
			name: "IsFilePath true with domains flag and example.com - should NOT add forward slash",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("domains", "example.com")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "domains",
				IsFilePath: true,
				Opts:       "",
			},
			want:               "example.com",
			wantErr:            false,
			checkNoSlashPrefix: true,
		},
		{
			name: "IsFilePath true with domains flag and subdomain.example.com - should NOT add forward slash",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("domains", "subdomain.example.com")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "domains",
				IsFilePath: true,
				Opts:       "",
			},
			want:               "subdomain.example.com",
			wantErr:            false,
			checkNoSlashPrefix: true,
		},
		{
			name: "IsFilePath true with domains flag and wildcard domain - should NOT add forward slash",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("domains", "*.example.com")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "domains",
				IsFilePath: true,
				Opts:       "",
			},
			want:               "*.example.com",
			wantErr:            false,
			checkNoSlashPrefix: true,
		},
		{
			name: "IsFilePath true with target flag and IP address - should NOT add forward slash",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("target", "192.168.1.1")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "target",
				IsFilePath: true,
				Opts:       "",
			},
			want:               "192.168.1.1",
			wantErr:            false,
			checkNoSlashPrefix: true,
		},
		{
			name: "IsFilePath true with non-existent file path value - should NOT add forward slash",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("config", "nonexistent-file.txt")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "config",
				IsFilePath: true,
				Opts:       "",
			},
			want:               "nonexistent-file.txt",
			wantErr:            false,
			checkNoSlashPrefix: true,
		},
		// ==========================================
		// Basic string flag tests
		// ==========================================
		{
			name: "basic string flag with simple value",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("name", "testvalue")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "name",
				Opts: "",
			},
			want:    "testvalue",
			wantErr: false,
		},
		{
			name: "basic string flag with empty value",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("name", "")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:           "name",
				DefaultFlagVal: "default",
				Opts:           "",
			},
			want:    "default",
			wantErr: false,
		},
		{
			name: "string flag with URL value",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("url", "https://example.com/path")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "url",
				Opts: "",
			},
			want:    "https://example.com/path",
			wantErr: false,
		},
		// ==========================================
		// Integer flag tests
		// ==========================================
		{
			name: "int flag with positive value",
			setupCmd: func() *cobra.Command {
				return createCmdWithIntFlag("count", 42, true)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "count",
				Opts: 0,
			},
			want:    42,
			wantErr: false,
		},
		{
			name: "int flag with zero value",
			setupCmd: func() *cobra.Command {
				return createCmdWithIntFlag("count", 0, true)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "count",
				Opts: 0,
			},
			want:    0,
			wantErr: false,
		},
		{
			name: "int flag with negative value",
			setupCmd: func() *cobra.Command {
				return createCmdWithIntFlag("offset", -10, true)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "offset",
				Opts: 0,
			},
			want:    -10,
			wantErr: false,
		},
		{
			name: "int flag not set uses default",
			setupCmd: func() *cobra.Command {
				return createCmdWithIntFlag("count", 0, false)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:           "count",
				DefaultFlagVal: "100",
				Opts:           0,
			},
			want:    100,
			wantErr: false,
		},
		// ==========================================
		// Boolean flag tests
		// ==========================================
		{
			name: "bool flag set to true",
			setupCmd: func() *cobra.Command {
				return createCmdWithBoolFlag("verbose", true, true)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "verbose",
				Opts: false,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "bool flag set to false",
			setupCmd: func() *cobra.Command {
				return createCmdWithBoolFlag("verbose", false, true)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "verbose",
				Opts: false,
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "bool flag not set uses default true",
			setupCmd: func() *cobra.Command {
				return createCmdWithBoolFlag("enabled", false, false)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:           "enabled",
				DefaultFlagVal: "true",
				Opts:           false,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "bool flag not set uses default false",
			setupCmd: func() *cobra.Command {
				return createCmdWithBoolFlag("disabled", false, false)
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:           "disabled",
				DefaultFlagVal: "false",
				Opts:           false,
			},
			want:    false,
			wantErr: false,
		},
		// ==========================================
		// Slice flag tests with comma separation
		// ==========================================
		{
			name: "slice flag with comma separated values and CommaInStringToSlice true",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("tags", "tag1,tag2,tag3")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:                 "tags",
				CommaInStringToSlice: true,
				Opts:                 []string{},
			},
			want:    []string{"tag1", "tag2", "tag3"},
			wantErr: false,
		},
		{
			name: "slice flag with single value",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("tags", "single")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:                 "tags",
				CommaInStringToSlice: true,
				Opts:                 []string{},
			},
			want:    []string{"single"},
			wantErr: false,
		},
		{
			name: "slice flag with comma values but CommaInStringToSlice false",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("tags", "tag1,tag2")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:                 "tags",
				CommaInStringToSlice: false,
				Opts:                 []string{},
			},
			want:    []string{"tag1,tag2"},
			wantErr: false,
		},
		{
			name: "slice flag with multiple domains comma separated",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("domains", "example.com,test.com,demo.org")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:                 "domains",
				CommaInStringToSlice: true,
				Opts:                 []string{},
			},
			want:    []string{"example.com", "test.com", "demo.org"},
			wantErr: false,
		},
		// ==========================================
		// Prefix tests
		// ==========================================
		{
			name: "flag with prefix",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("search-query", "", "test flag")
				_ = cmd.Flags().Set("search-query", "test")
				return cmd
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:   "query",
				Prefix: "search-",
				Opts:   "",
			},
			want:    "test",
			wantErr: false,
		},
		// ==========================================
		// IsFilePath false tests (control cases)
		// ==========================================
		{
			name: "IsFilePath false with domain-like value - returns as-is",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("target", "example.com")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "target",
				IsFilePath: false,
				Opts:       "",
			},
			want:    "example.com",
			wantErr: false,
		},
		// ==========================================
		// Default value tests
		// ==========================================
		{
			name: "string flag not set returns default",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("name", "", "test flag")
				return cmd
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:           "name",
				DefaultFlagVal: "defaultname",
				Opts:           "",
			},
			want:    "defaultname",
			wantErr: false,
		},
		{
			name: "slice default value with comma separation",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("items", "", "test flag")
				return cmd
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:                 "items",
				DefaultFlagVal:       "a,b,c",
				CommaInStringToSlice: true,
				Opts:                 []string{},
			},
			want:    []string{"a", "b", "c"},
			wantErr: false,
		},
		// ==========================================
		// Edge cases
		// ==========================================
		{
			name: "IsFilePath true with empty string value",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("path", "", "test flag")
				return cmd
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag:       "path",
				IsFilePath: true,
				Opts:       "",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "string with special characters",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("query", "test@example.com")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "query",
				Opts: "",
			},
			want:    "test@example.com",
			wantErr: false,
		},
		{
			name: "string with spaces",
			setupCmd: func() *cobra.Command {
				return createCmdWithStringFlag("message", "hello world")
			},
			lfcOpts: &LoadFromCommandOpts{
				Flag: "message",
				Opts: "",
			},
			want:    "hello world",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper state for each test
			viper.Reset()

			cmd := tt.setupCmd()
			got, err := ConfigureFlagOpts(cmd, tt.lfcOpts)

			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureFlagOpts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConfigureFlagOpts() got = %v, want %v", got, tt.want)
			}

			// Special check for no forward slash prefix
			if tt.checkNoSlashPrefix {
				if strVal, ok := got.(string); ok {
					if strings.HasPrefix(strVal, "/") {
						t.Errorf("ConfigureFlagOpts() value should NOT have forward slash prefix, got = %v", strVal)
					}
				}
			}
		})
	}
}

// TestConfigureFlagOpts_DomainsIsFilePath specifically tests the scenario where
// IsFilePath is true but the value is a domain name (not a file path).
// This is a critical test to ensure domain names like "example.com" are not
// incorrectly prefixed with a forward slash when IsFilePath is enabled.
func TestConfigureFlagOpts_DomainsIsFilePath(t *testing.T) {
	viper.Reset()

	domainTestCases := []struct {
		name   string
		domain string
	}{
		{"simple domain", "example.com"},
		{"subdomain", "www.example.com"},
		{"deep subdomain", "api.v2.example.com"},
		{"wildcard domain", "*.example.com"},
		{"hyphenated domain", "my-site.example.com"},
		{"numeric domain", "123.example.com"},
		{"top level domain only", "localhost"},
		{"domain with port style", "example.com:8080"},
		{"international domain", "münchen.example.com"},
	}

	for _, tc := range domainTestCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("domains", "", "target domains")
			_ = cmd.Flags().Set("domains", tc.domain)

			opts := &LoadFromCommandOpts{
				Flag:       "domains",
				IsFilePath: true,
				Opts:       "",
			}

			got, err := ConfigureFlagOpts(cmd, opts)
			if err != nil {
				t.Errorf("ConfigureFlagOpts() unexpected error = %v", err)
				return
			}

			strVal, ok := got.(string)
			if !ok {
				t.Errorf("ConfigureFlagOpts() expected string result, got %T", got)
				return
			}

			// The domain should NOT have a leading forward slash
			if strings.HasPrefix(strVal, "/") {
				t.Errorf("Domain %q should NOT have forward slash prefix, got %q", tc.domain, strVal)
			}

			// The value should match exactly what was passed
			if strVal != tc.domain {
				t.Errorf("ConfigureFlagOpts() got = %q, want %q", strVal, tc.domain)
			}
		})
	}
}

// TestConfigureFlagOpts_ExistingFilePath tests that existing file paths are resolved correctly
func TestConfigureFlagOpts_ExistingFilePath(t *testing.T) {
	viper.Reset()

	// Create a temporary file to test with
	tmpFile, err := os.CreateTemp("", "testfile*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "config file path")
	_ = cmd.Flags().Set("config", tmpFile.Name())

	opts := &LoadFromCommandOpts{
		Flag:       "config",
		IsFilePath: true,
		Opts:       "",
	}

	got, err := ConfigureFlagOpts(cmd, opts)
	if err != nil {
		t.Errorf("ConfigureFlagOpts() unexpected error = %v", err)
		return
	}

	strVal, ok := got.(string)
	if !ok {
		t.Errorf("ConfigureFlagOpts() expected string result, got %T", got)
		return
	}

	// For existing files, the path should be resolved to an absolute path
	if !strings.HasPrefix(strVal, "/") {
		t.Errorf("Existing file path should be resolved to absolute path, got %q", strVal)
	}
}

// TestConfigureFlagOpts_CommaInStringToSlice_WithIsFilePath tests the interaction
// between CommaInStringToSlice and string values
func TestConfigureFlagOpts_CommaInStringToSlice_WithIsFilePath(t *testing.T) {
	viper.Reset()

	cmd := &cobra.Command{}
	cmd.Flags().String("targets", "", "target list")
	_ = cmd.Flags().Set("targets", "example.com,test.com,demo.org")

	// When Opts is a string (not slice), CommaInStringToSlice with IsFilePath
	opts := &LoadFromCommandOpts{
		Flag:                 "targets",
		IsFilePath:           true,
		CommaInStringToSlice: true,
		Opts:                 "",
	}

	got, err := ConfigureFlagOpts(cmd, opts)
	if err != nil {
		t.Errorf("ConfigureFlagOpts() unexpected error = %v", err)
		return
	}

	// With Opts as string and IsFilePath true, the comma-separated value
	// should be treated as a single string (file path that doesn't exist)
	strVal, ok := got.(string)
	if !ok {
		t.Errorf("ConfigureFlagOpts() expected string result, got %T", got)
		return
	}

	// Should not have leading slash since file doesn't exist
	if strings.HasPrefix(strVal, "/") {
		t.Errorf("Non-existent path should NOT have forward slash prefix, got %q", strVal)
	}
}
