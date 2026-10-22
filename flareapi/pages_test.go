package flareapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
