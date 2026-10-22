package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		{"groups", []string{"identifier-groups", "list"}, "/firework/v2/assets/groups/", `{"assets_groups":{"id":7,"name":"Production","feed_id":123,"feed_owner_id":456}}`},
		{"identifiers", []string{"identifiers", "list", "--is-disabled", "false", "--types", "domain", "--types", "keyword"}, "/firework/v4/identifiers/", `{"items":[{"id":8,"name":"Production","is_disabled":false}],"next":null}`},
		{"alerts", []string{"alerts", "list", "--asset-id", "8"}, "/firework/v2/assets/8/alerts", `{"alerts":{"id":9,"name":"Production","type":"email","frequency":60}}`},
		{"group alerts", []string{"group-alerts", "list", "--assets-group-id", "7"}, "/firework/v2/assets/groups/7/alerts", `{"alerts":[{"id":9,"name":"Production"}]}`},
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
			if err := writeFile(command, outputPath, func() (io.ReadCloser, error) {
				t.Fatal("existing file must be rejected before obtaining a response")
				return nil, nil
			}); err == nil {
				t.Fatal("overwrote existing download")
			}
		})
	}
}

func TestOutputDestinationValidatedBeforeRequests(test *testing.T) {
	test.Parallel()
	for _, mode := range []string{"stream", "all"} {
		for _, kind := range []string{"existing file", "directory", "missing parent", "symlink"} {
			test.Run(mode+"/"+kind, func(test *testing.T) {
				test.Parallel()
				path := invalidOutputPath(test, kind)
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					writer.WriteHeader(http.StatusInternalServerError)
				}))
				defer server.Close()
				arguments := []string{"v2", "post_assets_groups", "--body", `{"name":"Production"}`}
				if mode == "all" {
					arguments = []string{"v4", "global_search_events_global__search_post", "--body", `{}`, "--all"}
				}
				command := NewCommand()
				command.SetOut(io.Discard)
				command.SetErr(io.Discard)
				command.SetArgs(append(arguments, "--output-file", path, "--api-key", "fixture", "--api-token", "", "--auth-tenant-id", "0", "--base-url", server.URL))
				if err := command.ExecuteContext(test.Context()); err == nil {
					test.Fatal("expected invalid output destination error")
				}
				if calls.Load() != 0 {
					test.Fatalf("invalid destination caused %d authentication/API requests", calls.Load())
				}
				if kind == "existing file" {
					contents, err := os.ReadFile(path)
					if err != nil || string(contents) != "original" {
						test.Fatalf("existing file changed: %q, %v", contents, err)
					}
				}
			})
		}
	}
}

func invalidOutputPath(test *testing.T, kind string) string {
	test.Helper()
	directory := test.TempDir()
	path := filepath.Join(directory, "result.json")
	switch kind {
	case "existing file":
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			test.Fatal(err)
		}
	case "directory":
		path = directory
	case "missing parent":
		path = filepath.Join(directory, "missing", "result.json")
	case "symlink":
		if err := os.Symlink(filepath.Join(directory, "missing-target"), path); err != nil {
			test.Skipf("symlinks unavailable: %v", err)
		}
	}
	return path
}

func TestDownloadReservationAndCleanup(test *testing.T) {
	test.Parallel()
	for _, fixture := range []struct {
		name      string
		status    int
		body      string
		all       bool
		cancel    bool
		wantError bool
	}{
		{"success", 200, `{"items":[{"id":1}],"next":null}`, false, false, false},
		{"empty success", 204, "", false, false, false},
		{"HTTP failure", 403, `{"detail":"denied"}`, false, false, true},
		{"aggregate success", 200, `{"items":[{"id":1}],"next":null}`, true, false, false},
		{"aggregate decode failure", 200, `{"items":[],"next":42}`, true, false, true},
		{"canceled", 200, `{}`, false, true, true},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			path := filepath.Join(test.TempDir(), "result.json")
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				info, err := os.Stat(path)
				if err != nil {
					test.Errorf("output not reserved before request: %v", err)
				} else if info.Mode().Perm() != 0600 || info.Size() != 0 {
					test.Errorf("invalid reservation: permissions=%v, size=%d", info.Mode().Perm(), info.Size())
				}
				writer.WriteHeader(fixture.status)
				_, _ = io.WriteString(writer, fixture.body)
			}))
			defer server.Close()
			command := NewCommand()
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			arguments := []string{"v4", "global_search_events_global__search_post", "--body", `{}`, "--output-file", path, "--api-key", "", "--api-token", "fixture", "--auth-tenant-id", "0", "--base-url", server.URL}
			if fixture.all {
				arguments = append(arguments, "--all", "--page-delay", "0s")
			}
			command.SetArgs(arguments)
			ctx, cancel := context.WithCancel(test.Context())
			defer cancel()
			if fixture.cancel {
				cancel()
			}
			err := command.ExecuteContext(ctx)
			if (err != nil) != fixture.wantError {
				test.Fatalf("error=%v, wantError=%v", err, fixture.wantError)
			}
			if fixture.wantError {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					test.Fatalf("failed request left reserved file: %v", err)
				}
				return
			}
			contents, err := os.ReadFile(path)
			if err != nil || string(contents) != fixture.body {
				test.Fatalf("output=%q, error=%v", contents, err)
			}
		})
	}
}

func TestWriteFilePreservesPartialDataAndErrors(test *testing.T) {
	test.Parallel()
	failure := errors.New("fixture transfer failure")
	for _, path := range []string{filepath.Join(test.TempDir(), "partial.bin"), "-"} {
		test.Run(filepath.Base(path), func(test *testing.T) {
			reader := &failingResponseReader{failure: failure}
			var stdout bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&stdout)
			err := writeFile(command, path, func() (io.ReadCloser, error) { return reader, nil })
			if !errors.Is(err, failure) || !reader.closed {
				test.Fatalf("transfer error or close lost: error=%v closed=%v", err, reader.closed)
			}
			contents := stdout.Bytes()
			if path != "-" {
				var readError error
				contents, readError = os.ReadFile(path)
				if readError != nil {
					test.Fatal(readError)
				}
			}
			if string(contents) != "partial" {
				test.Fatalf("partial data lost: %q", contents)
			}
		})
	}
}

type failingResponseReader struct {
	failure error
	sent    bool
	closed  bool
}

func (reader *failingResponseReader) Read(destination []byte) (int, error) {
	if reader.sent {
		return 0, reader.failure
	}
	reader.sent = true
	return copy(destination, "partial"), reader.failure
}

func (reader *failingResponseReader) Close() error {
	reader.closed = true
	return nil
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

func TestCursorMessagesAndRawJSON(test *testing.T) {
	test.Parallel()
	for _, fixture := range []struct {
		name   string
		args   []string
		body   string
		resume string
	}{
		{"legacy query", []string{"v2", "get_search"}, `{"items":[],"search_after":"resume\u001b[31m"}`, "--search-after"},
		{"modern query", []string{"v4", "list_identifiers_identifiers__get"}, `{"items":[],"next":"resume"}`, "--from"},
		{"body", []string{"v4", "global_search_events_global__search_post", "--body", `{}`}, `{"items":[],"next":"resume"}`, "JSON body's from field"},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, fixture.body)
			}))
			defer server.Close()
			for _, format := range []string{"table", "json"} {
				command := NewCommand()
				var stdout, stderr bytes.Buffer
				command.SetOut(&stdout)
				command.SetErr(&stderr)
				command.SetArgs(append(fixture.args, "--api-key", "", "--api-token", "fixture", "--auth-tenant-id", "0", "--base-url", server.URL, "--format", format, "--all", "--max-pages", "1"))
				if err := command.ExecuteContext(test.Context()); err != nil {
					test.Fatal(err)
				}
				if format == "json" {
					if !json.Valid(stdout.Bytes()) || stderr.Len() != 0 || !strings.Contains(stdout.String(), "resume") {
						test.Fatalf("invalid JSON/cursor output: stdout=%s stderr=%s", stdout.String(), stderr.String())
					}
				} else if !strings.Contains(stderr.String(), fixture.resume) || strings.ContainsRune(stderr.String(), '\x1b') || strings.Contains(stdout.String(), "resume") {
					test.Fatalf("incorrect cursor guidance: stdout=%s stderr=%q", stdout.String(), stderr.String())
				}
			}
		})
	}
}
