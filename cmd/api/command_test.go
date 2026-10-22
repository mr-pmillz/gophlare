package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gophlare/flareapi"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestEveryOperationHasWorkingCLI(t *testing.T) {
	t.Parallel()
	for _, operation := range flareapi.Operations() {
		t.Run(operation.Version+"/"+operation.ID, func(t *testing.T) {
			t.Parallel()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.Method != operation.Method {
					t.Errorf("method = %s, want %s", request.Method, operation.Method)
				}
				if request.Header.Get("Authorization") != "Bearer fixture" {
					t.Error("missing authentication")
				}
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, `{"items":[{"id":9007199254740993,"name":"fixture"}],"next":null}`)
			}))
			defer server.Close()
			arguments := []string{operation.Version, operation.ID, "--api-token", "fixture", "--api-key", "", "--auth-tenant-id", "0", "--base-url", server.URL, "--format", "json"}
			arguments = append(arguments, fixtureArguments(operation)...)
			if operation.HasBody {
				arguments = append(arguments, "--body", "{}")
			}
			command := NewCommand()
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			command.SetArgs(arguments)
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), "9007199254740993") {
				t.Fatalf("calls=%d, output=%s, stderr=%s", calls, stdout.String(), stderr.String())
			}
		})
	}
}

func fixtureArguments(operation flareapi.Operation) []string {
	var arguments []string
	for _, parameter := range operation.Parameters {
		value := "fixture"
		switch parameter.Type {
		case "integer", "number":
			value = "1"
		case "boolean":
			value = "false"
		case "array":
			if parameter.ItemType == "integer" {
				value = "1"
			}
		}
		if parameter.Format == "uuid" {
			value = "123e4567-e89b-12d3-a456-426614174000"
		}
		arguments = append(arguments, "--"+parameterFlag(parameter.Name), value)
	}
	return arguments
}

func TestResourceCommands(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
		path string
		body string
	}{
		{"groups", []string{"identifier-groups", "list"}, "/firework/v2/assets/groups/", `{"items":[{"id":7,"name":"Production"}]}`},
		{"identifiers", []string{"identifiers", "list", "--is-disabled", "false", "--types", "domain", "--types", "keyword"}, "/firework/v4/identifiers/", `{"items":[{"id":8,"name":"Production","is_disabled":false}],"next":null}`},
		{"alerts", []string{"alerts", "list", "--asset-id", "8"}, "/firework/v2/assets/8/alerts", `{"items":[{"id":9,"name":"Production","type":"email","frequency":60}]}`},
		{"group alerts", []string{"group-alerts", "list", "--assets-group-id", "7"}, "/firework/v2/assets/groups/7/alerts", `[{"id":9,"name":"Production"}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != test.path {
					t.Errorf("path = %s, want %s", request.URL.Path, test.path)
				}
				if test.name == "identifiers" {
					if request.URL.Query().Get("is_disabled") != "false" || len(request.URL.Query()["types"]) != 2 {
						t.Errorf("query = %s", request.URL.RawQuery)
					}
				}
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			root := &cobra.Command{Use: "gophlare"}
			root.AddCommand(ResourceCommands()...)
			root.SetArgs(append(test.args, "--api-key", "", "--api-token", "fixture", "--auth-tenant-id", "0", "--base-url", server.URL))
			var stdout bytes.Buffer
			root.SetOut(&stdout)
			if err := root.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "┌") || !strings.Contains(stdout.String(), "Production") {
				t.Fatalf("missing fancy table:\n%s", stdout.String())
			}
		})
	}
}

func TestRequestBodySourcesAndDownloads(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	bodyFile := filepath.Join(directory, "request.json")
	if err := os.WriteFile(bodyFile, []byte(`{"name":"fixture","is_disabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"-", "@" + bodyFile} {
		t.Run(source, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil || !strings.Contains(string(body), `"is_disabled":false`) {
					t.Errorf("body = %s, err = %v", body, err)
				}
				_, _ = io.WriteString(writer, "binary\x00fixture")
			}))
			defer server.Close()
			outputPath := filepath.Join(t.TempDir(), "download.bin")
			command := NewCommand()
			command.SetIn(strings.NewReader(`{"is_disabled":false}`))
			command.SetArgs([]string{"v2", "post_assets_groups", "--api-key", "", "--api-token", "fixture", "--auth-tenant-id", "0", "--base-url", server.URL, "--body", source, "--output-file", outputPath})
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(outputPath)
			if err != nil || string(data) != "binary\x00fixture" {
				t.Fatalf("download = %q, err = %v", data, err)
			}
			info, err := os.Stat(outputPath)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("download permissions: %v, %v", info, err)
			}
			if err := writeFile(command, outputPath, strings.NewReader("overwrite")); err == nil {
				t.Fatal("overwrote existing download")
			}
		})
	}
}

func TestValidationBeforeHTTP(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing path", []string{"v2", "get_asset_alerts"}},
		{"wrong number", []string{"v2", "get_asset_alerts", "--asset-id", "bad"}},
		{"missing body", []string{"v2", "post_assets_groups"}},
		{"malformed body", []string{"v2", "post_assets_groups", "--body", "{"}},
		{"format", []string{"v2", "get_assets_groups", "--format", "csv"}},
		{"pagination", []string{"v2", "get_assets_groups", "--all"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				t.Error("invalid input sent a request")
				writer.WriteHeader(http.StatusBadRequest)
			}))
			defer server.Close()
			command := NewCommand()
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			command.SetArgs(append(test.args, "--api-key", "", "--api-token", "fixture", "--auth-tenant-id", "0", "--base-url", server.URL))
			if err := command.ExecuteContext(t.Context()); err == nil {
				t.Fatal("expected validation error")
			}
			if stdout.Len() != 0 {
				t.Errorf("error polluted stdout: %s", stdout.String())
			}
		})
	}
}

func TestClientConfigPrecedence(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("API_KEYS.FLARE_API", "config-key")
	viper.Set("API_KEYS.FLARE_TENANT_ID", 123)
	t.Setenv("GOFLARE_API_KEY", "env-key")
	for _, test := range []struct {
		name string
		args []string
		key  string
	}{
		{"environment", nil, "env-key"},
		{"flag", []string{"--api-key", "flag-key"}, "flag-key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "fixture"}
			settings := addFlags(command)
			command.RunE = func(command *cobra.Command, _ []string) error {
				config := settings.clientConfig(command)
				if config.APIKey != test.key || config.TenantID != 123 {
					return fmt.Errorf("unexpected config precedence")
				}
				return nil
			}
			command.SetArgs(test.args)
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
