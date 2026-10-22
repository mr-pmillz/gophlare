package flareapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestOperationsMatchSpecs(t *testing.T) {
	t.Parallel()
	operations := Operations()
	seen := make(map[string]bool)
	total := 0
	for _, version := range []string{"v2", "v3", "v4"} {
		data, err := os.ReadFile("../firework-" + version + "-openapi.json")
		if err != nil {
			t.Fatal(err)
		}
		var spec struct {
			Paths map[string]map[string]struct {
				ID string `json:"operationId"`
			} `json:"paths"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			t.Fatal(err)
		}
		for path, methods := range spec.Paths {
			for method, definition := range methods {
				if definition.ID == "" {
					continue
				}
				total++
				operation, err := FindOperation(version, definition.ID)
				if err != nil {
					t.Fatal(err)
				}
				if operation.Path != path || operation.Method != strings.ToUpper(method) {
					t.Errorf("%s: got %s %s; want %s %s", definition.ID, operation.Method, operation.Path, method, path)
				}
				key := version + ":" + definition.ID
				if seen[key] {
					t.Fatalf("duplicate operation %s", key)
				}
				seen[key] = true
			}
		}
	}
	if total == 0 || total != len(operations) {
		t.Fatalf("spec operations = %d; registry = %d", total, len(operations))
	}
}

func TestEveryOperationSendsGeneratedRequest(t *testing.T) {
	t.Parallel()
	for _, operation := range Operations() {
		t.Run(operation.Version+"/"+operation.ID, func(t *testing.T) {
			t.Parallel()
			input := fixtureRequest(operation)
			expectedPath := operation.Path
			for _, parameter := range operation.Parameters {
				if parameter.In == "path" {
					expectedPath = strings.ReplaceAll(expectedPath, "{"+parameter.Name+"}", strings.Trim(string(input.Parameters[parameter.Name]), `"`))
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assertGeneratedRequest(t, request, operation, input, expectedPath)
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, `{"items":[],"next":null}`)
			}))
			defer server.Close()
			client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Call(t.Context(), operation, input); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertGeneratedRequest(t *testing.T, request *http.Request, operation Operation, input Request, expectedPath string) {
	t.Helper()
	if request.Method != operation.Method || request.URL.Path != expectedPath {
		t.Errorf("request = %s %s; want %s %s", request.Method, request.URL.Path, operation.Method, expectedPath)
	}
	if request.Header.Get("Authorization") != "Bearer fixture" {
		t.Error("missing bearer authentication")
	}
	for _, parameter := range operation.Parameters {
		if parameter.In == "query" && !request.URL.Query().Has(parameter.Name) {
			t.Errorf("missing query parameter %s", parameter.Name)
		}
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != string(input.Body) {
		t.Errorf("request body = %s; error = %v", body, err)
	}
}

func fixtureRequest(operation Operation) Request {
	input := Request{Parameters: make(map[string]json.RawMessage)}
	for _, parameter := range operation.Parameters {
		value := `"fixture"`
		switch parameter.Type {
		case "integer", "number":
			value = "12"
		case "boolean":
			value = "false"
		case "array":
			value = `["fixture","another"]`
			if parameter.ItemType == "integer" {
				value = `[1,2]`
			}
		}
		if parameter.Format == "uuid" {
			value = `"123e4567-e89b-12d3-a456-426614174000"`
		}
		input.Parameters[parameter.Name] = json.RawMessage(value)
	}
	if operation.HasBody {
		input.Body = json.RawMessage(`{"explicit_false":false,"zero":0,"clear":null}`)
	}
	return input
}

func TestBuildRequestValidation(t *testing.T) {
	t.Parallel()
	operation, err := FindOperation("v4", "update_identifier_by_id_public_identifiers__identifier_id__put")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		input Request
	}{
		{"missing path", Request{Body: json.RawMessage(`{}`)}},
		{"missing body", Request{Parameters: map[string]json.RawMessage{"identifier_id": json.RawMessage(`1`)}}},
		{"wrong path type", Request{Parameters: map[string]json.RawMessage{"identifier_id": json.RawMessage(`"bad"`)}, Body: json.RawMessage(`{}`)}},
		{"unknown parameter", Request{Parameters: map[string]json.RawMessage{"identifier_id": json.RawMessage(`1`), "oops": json.RawMessage(`1`)}, Body: json.RawMessage(`{}`)}},
		{"invalid JSON", Request{Parameters: map[string]json.RawMessage{"identifier_id": json.RawMessage(`1`)}, Body: json.RawMessage(`{`)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := operation.BuildRequest(context.Background(), DefaultBaseURL, test.input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBuildRequestPreservesServerPrefixAndEscapesParameters(t *testing.T) {
	t.Parallel()
	operation, err := FindOperation("v2", "get_activity_assistance_resource")
	if err != nil {
		t.Fatal(err)
	}
	input := Request{Parameters: map[string]json.RawMessage{
		"index": json.RawMessage(`"a/b"`), "source": json.RawMessage(`"source?query"`), "id": json.RawMessage(`"#fragment"`),
	}}
	request, err := operation.BuildRequest(t.Context(), "https://example.test/prefix", input)
	if err != nil {
		t.Fatal(err)
	}
	if request.URL.Host != "example.test" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		t.Fatalf("parameters escaped their path segments: %s", request.URL)
	}
	if want := "/prefix/firework/v2/activities/a%2Fb/source%3Fquery/%23fragment/ai_assistance"; request.URL.EscapedPath() != want {
		t.Fatalf("escaped path = %s, want %s", request.URL.EscapedPath(), want)
	}
}

func TestOperationResponseKeys(test *testing.T) {
	test.Parallel()
	for _, fixture := range []struct {
		name string
		key  string
	}{
		{"get_assets_groups", "assets_groups"},
		{"get_asset_alerts", "alerts"},
		{"get_assets_group_alerts", "alerts"},
		{"get_assets_group_api", "assets_group"},
		{"get_current_user_profile", "profile"},
		{"get_current_user_tenants", "tenants"},
		{"get_search", ""},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			operation, err := FindOperation("v2", fixture.name)
			if err != nil {
				test.Fatal(err)
			}
			if operation.ResponseKey != fixture.key {
				test.Fatalf("response key=%q, want %q", operation.ResponseKey, fixture.key)
			}
		})
	}
}
