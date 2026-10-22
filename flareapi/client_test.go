package flareapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/gophlare/flareapi/fireworkv4"
)

func TestClientAuthenticationAndTypedClients(t *testing.T) {
	t.Parallel()
	var tokens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/tokens/generate" {
			if request.Header.Get("Authorization") != "test-key" || request.Header.Get("Content-Type") != "application/json" {
				t.Error("wrong token request headers")
			}
			var body struct {
				TenantID int `json:"tenant_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.TenantID != 7 {
				t.Errorf("tenant body: %+v, %v", body, err)
			}
			fmt.Fprintf(writer, `{"token":"token-%d"}`, tokens.Add(1))
			return
		}
		if request.Header.Get("Authorization") == "" || request.Header.Get("User-Agent") != "test-agent" {
			t.Error("missing API request headers")
		}
		_, _ = io.WriteString(writer, `{"items":[],"next":null}`)
	}))
	defer server.Close()
	client, err := NewClient(Config{APIKey: "test-key", TenantID: 7, BaseURL: server.URL, UserAgent: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			response, err := client.V2.GetAssetsGroupsWithResponse(t.Context())
			if err != nil || response.JSON200 == nil {
				t.Errorf("v2 response: %+v, %v", response, err)
			}
		})
	}
	workers.Wait()
	if tokens.Load() != 1 {
		t.Fatalf("token requests = %d, want 1", tokens.Load())
	}
	client.session.expiresAt = time.Now().Add(-time.Minute)
	if _, err := client.V3.GetIdentifiersEndpointWithResponse(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	response, err := client.V4.ListIdentifiersIdentifiersGetWithResponse(t.Context(), nil)
	if err != nil || response.JSON200 == nil {
		t.Fatalf("v4 response: %+v, %v", response, err)
	}
	if tokens.Load() != 2 {
		t.Fatalf("token requests after refresh = %d, want 2", tokens.Load())
	}
}

func TestClientHTTPFailuresAreNotRetried(t *testing.T) {
	t.Parallel()
	for _, status := range []int{400, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.Header().Set("Retry-After", "10")
				writer.WriteHeader(status)
				_, _ = io.WriteString(writer, `{"error":{"message":"fixture failure"}}`)
			}))
			defer server.Close()
			client, err := NewClient(Config{Token: "fixture", BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			operation, err := FindOperation("v2", "post_assets_groups")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Call(t.Context(), operation, Request{Body: json.RawMessage(`{"name":"group"}`)})
			var apiError *APIError
			if !errors.As(err, &apiError) || apiError.StatusCode != status || apiError.Header.Get("Retry-After") != "10" {
				t.Fatalf("API error = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("mutation replayed %d times", calls.Load())
			}
		})
	}
}

func TestClientCancellationAndOriginProtection(t *testing.T) {
	t.Parallel()
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		leaked.Store(true)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err := NewClient(Config{Token: "secret", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := FindOperation("v2", "get_assets_groups")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(t.Context(), operation, Request{}); err == nil {
		t.Error("cross-origin redirect accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Call(ctx, operation, Request{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancellation = %v", err)
	}
	if leaked.Load() {
		t.Fatal("request reached another origin")
	}
}

func TestGeneratedModelsPreserveExplicitFalse(t *testing.T) {
	t.Parallel()
	disabled := false
	data, err := json.Marshal(fireworkv4.ListIdentifiersIdentifiersGetParams{IsDisabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["is_disabled"]) != "false" {
		t.Fatalf("explicit false lost: %s", data)
	}
	var update fireworkv4.PublicIdentifierUpdateRequestBody
	update.IsDisabled.Set(false)
	update.GroupID.SetNull()
	update.Name.Set("")
	data, err = json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["is_disabled"]) != "false" || string(fields["group_id"]) != "null" || string(fields["name"]) != `""` {
		t.Fatalf("explicit false/null/empty values lost: %s", data)
	}
	update.IsDisabled.SetUnspecified()
	update.GroupID.SetUnspecified()
	update.Name.SetUnspecified()
	data, err = json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	fields = make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"is_disabled", "group_id", "name"} {
		if _, exists := fields[key]; exists {
			t.Errorf("unspecified field %s serialized: %s", key, data)
		}
	}
}

func TestClientCanceledWhileWaitingForToken(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/tokens/generate" {
			close(started)
			<-release
			_, _ = io.WriteString(writer, `{"token":"fixture"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"items":[]}`)
	}))
	defer server.Close()
	defer close(release)
	client, err := NewClient(Config{APIKey: "fixture", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := FindOperation("v2", "get_assets_groups")
	if err != nil {
		t.Fatal(err)
	}
	firstContext, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = client.Call(firstContext, operation, Request{})
	}()
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Call(ctx, operation, Request{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("token waiter did not observe cancellation: %v", err)
	}
	cancelFirst()
	<-firstDone
}
