package flareapi

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCollect(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		id   string
		body string
	}{
		{"query", "list_identifiers_identifiers__get", ""},
		{"body", "global_search_events_global__search_post", `{"query":{"type":"query_string","query_string":"example"},"size":5}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				servePaginationFixture(t, writer, request, calls, test.body != "")
			}))
			defer server.Close()
			client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			operation, err := FindOperation("v4", test.id)
			if err != nil {
				t.Fatal(err)
			}
			input := Request{Body: json.RawMessage(test.body)}
			response, err := client.Collect(t.Context(), operation, input, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 3 || !strings.Contains(string(response.Body), "9007199254740993") || !strings.Contains(string(response.Body), `"next":null`) {
				t.Fatalf("calls=%d, body=%s", calls, response.Body)
			}
			if string(input.Body) != test.body {
				t.Fatal("collect mutated caller's input")
			}
		})
	}
}

func TestCollectV2CursorVariants(test *testing.T) {
	test.Parallel()
	for _, identifier := range []string{"get_search", "post_search", "get_current_user_home_feed", "get_asset_feed", "get_assets_group_feed"} {
		for _, field := range []string{"search_after", "next"} {
			test.Run(identifier+"/"+field, func(test *testing.T) {
				testCollectV2CursorVariant(test, identifier, field)
			})
		}
	}
}

func testCollectV2CursorVariant(test *testing.T, identifier, field string) {
	test.Helper()
	test.Parallel()
	operation, err := FindOperation("v2", identifier)
	if err != nil {
		test.Fatal(err)
	}
	parameter := operation.PageCursors[field]
	if parameter == "" {
		test.Fatalf("missing %s pagination metadata", field)
	}
	input := Request{Parameters: map[string]json.RawMessage{
		"query": json.RawMessage(`"example.test"`), "size": json.RawMessage(`5`),
		"search_after": json.RawMessage(`"start"`),
	}}
	for _, argument := range operation.Parameters {
		if argument.In == "path" {
			input.Parameters[argument.Name] = json.RawMessage(`123`)
		}
	}
	if operation.HasBody {
		input.Body = json.RawMessage(`{}`)
	}
	before, err := json.Marshal(input)
	if err != nil {
		test.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		serveV2CursorPage(test, writer, request, operation, field, calls.Add(1))
	}))
	defer server.Close()
	client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
	if err != nil {
		test.Fatal(err)
	}
	response, err := client.Collect(test.Context(), operation, input, 10, 0)
	if err != nil {
		test.Fatal(err)
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
		Hits  int               `json:"nb_hits"`
	}
	if err := json.Unmarshal(response.Body, &envelope); err != nil {
		test.Fatal(err)
	}
	if calls.Load() != 3 || len(envelope.Items) != 2 || envelope.Hits != 2 || !strings.Contains(string(response.Body), "9007199254740993") {
		test.Fatalf("calls=%d response=%s", calls.Load(), response.Body)
	}
	after, err := json.Marshal(input)
	if err != nil || string(after) != string(before) {
		test.Fatalf("input mutated: %s; error=%v", after, err)
	}
}

func serveV2CursorPage(test *testing.T, writer http.ResponseWriter, request *http.Request, operation Operation, field string, call int32) {
	test.Helper()
	parameter := operation.PageCursors[field]
	query := request.URL.Query()
	if query.Get("query") != "example.test" || query.Get("size") != "5" {
		test.Errorf("lost filters: %s", request.URL.RawQuery)
	}
	if call > 1 {
		want := "opaque +/= cursor"
		if call == 3 {
			want = "null"
		}
		if query.Get(parameter) != want {
			test.Errorf("%s = %q, want %q", parameter, query.Get(parameter), want)
		}
		for _, alternative := range operation.PageCursors {
			if alternative != parameter && query.Has(alternative) {
				test.Errorf("stale cursor %s was retained", alternative)
			}
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	switch call {
	case 1:
		_, _ = fmt.Fprintf(writer, `{"items":[],%q:"opaque +/= cursor","nb_hits":2}`, field)
	case 2:
		_, _ = fmt.Fprintf(writer, `{"items":[{"id":9007199254740993}],%q:"null","nb_hits":2}`, field)
	default:
		_, _ = fmt.Fprintf(writer, `{"items":[{"id":2}],%q:null,"nb_hits":2}`, field)
	}
}

func TestCollectLegacyLimitsAndErrors(test *testing.T) {
	test.Parallel()
	operation, err := FindOperation("v2", "get_search")
	if err != nil {
		test.Fatal(err)
	}
	for _, fixture := range []struct {
		name      string
		response  string
		initial   string
		maxPages  int
		wantCalls int32
		wantError string
	}{
		{"bounded", `{"items":[{"id":1}],"search_after":"resume"}`, "", 1, 1, ""},
		{"repeated", `{"items":[],"search_after":"same"}`, "", 10, 2, "repeated"},
		{"repeated initial", `{"items":[],"search_after":"same"}`, `"same"`, 10, 1, "repeated"},
		{"invalid response cursor", `{"items":[],"search_after":42}`, "", 10, 1, "decode search_after cursor"},
		{"invalid initial cursor", `{"items":[]}`, `42`, 10, 0, "decode search_after cursor"},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(writer, fixture.response)
			}))
			defer server.Close()
			client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
			if err != nil {
				test.Fatal(err)
			}
			input := Request{Parameters: make(map[string]json.RawMessage)}
			if fixture.initial != "" {
				input.Parameters["search_after"] = json.RawMessage(fixture.initial)
			}
			response, err := client.Collect(test.Context(), operation, input, fixture.maxPages, 0)
			if fixture.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), fixture.wantError) {
					test.Fatalf("expected %q error, got %v", fixture.wantError, err)
				}
			} else if err != nil || !strings.Contains(string(response.Body), `"search_after":"resume"`) {
				test.Fatalf("response=%v, error=%v", response, err)
			}
			if calls.Load() != fixture.wantCalls {
				test.Errorf("calls=%d, want %d", calls.Load(), fixture.wantCalls)
			}
		})
	}
}

func TestNextCursorAndMetadataIsolation(test *testing.T) {
	test.Parallel()
	operation, err := FindOperation("v2", "get_search")
	if err != nil {
		test.Fatal(err)
	}
	for _, fixture := range []struct {
		name  string
		body  string
		field string
		value string
	}{
		{"legacy", `{"search_after":"legacy"}`, "search_after", "legacy"},
		{"modern precedence", `{"next":"modern","search_after":"legacy"}`, "next", "modern"},
		{"modern terminal", `{"next":null,"search_after":"stale"}`, "next", ""},
		{"legacy terminal", `{"search_after":null}`, "search_after", ""},
		{"missing", `{"items":[]}`, "", ""},
		{"literal null", `{"search_after":"null"}`, "search_after", "null"},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			field, value, err := operation.NextCursor([]byte(fixture.body))
			if err != nil || field != fixture.field || value != fixture.value {
				test.Fatalf("cursor=(%q,%q), error=%v", field, value, err)
			}
		})
	}
	want := maps.Clone(operation.PageCursors)
	operation.PageCursors["next"] = "modified"
	fresh, err := FindOperation("v2", "get_search")
	if err != nil || !maps.Equal(fresh.PageCursors, want) {
		test.Fatalf("lookup metadata was shared: %+v, %v", fresh, err)
	}
	for _, candidate := range Operations() {
		if candidate.ID == "get_search" {
			candidate.PageCursors["next"] = "modified again"
		}
	}
	fresh, err = FindOperation("v2", "get_search")
	if err != nil || !maps.Equal(fresh.PageCursors, want) {
		test.Fatalf("list metadata was shared: %+v, %v", fresh, err)
	}
}

func servePaginationFixture(t *testing.T, writer http.ResponseWriter, request *http.Request, calls int, hasBody bool) {
	t.Helper()
	cursor := request.URL.Query().Get("from")
	if hasBody {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if raw := body["from"]; raw != nil {
			if err := json.Unmarshal(raw, &cursor); err != nil {
				t.Error(err)
			}
		}
		if string(body["size"]) != "5" || body["query"] == nil {
			t.Error("pagination discarded original body filters")
		}
	}
	switch calls {
	case 1:
		_, _ = io.WriteString(writer, `{"items":[],"next":"a+/= cursor"}`)
	case 2:
		if cursor != "a+/= cursor" {
			t.Errorf("cursor = %q", cursor)
		}
		_, _ = io.WriteString(writer, `{"items":[{"id":9007199254740993}],"next":"null"}`)
	default:
		if cursor != "null" {
			t.Errorf("opaque cursor = %q, want literal null string", cursor)
		}
		_, _ = io.WriteString(writer, `{"items":[{"id":2}],"next":null}`)
	}
}

func TestCollectBoundsAndRepeatedCursor(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"items":[],"next":"same"}`)
	}))
	defer server.Close()
	client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := FindOperation("v4", "list_identifiers_identifiers__get")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Collect(t.Context(), operation, Request{}, 1, 0)
	if err != nil || !strings.Contains(string(response.Body), `"next":"same"`) {
		t.Fatalf("bounded response=%v, err=%v", response, err)
	}
	if _, err := client.Collect(t.Context(), operation, Request{}, 10, 0); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("expected repeated cursor error: %v", err)
	}
}
