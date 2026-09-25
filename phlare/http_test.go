package phlare

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDoReqWithHeadersSurfacesQuotaHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Flare-Global-Searches-Remaining", "8998")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewHTTPClientWithTimeOut(false, 10)
	target := map[string]bool{}

	status, hdr, err := c.DoReqWithHeaders(srv.URL, "GET", &target, nil, nil, nil)
	if err != nil {
		t.Fatalf("DoReqWithHeaders() error = %v", err)
	}

	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if got := hdr.Get("X-Flare-Global-Searches-Remaining"); got != "8998" {
		t.Errorf("remaining header = %q, want %q", got, "8998")
	}
	if !target["ok"] {
		t.Error("response body was not decoded into target")
	}
}

// TestDoReqWithHeadersReturnsHeadersOnNon2xx matters because Flare returns
// quota headers alongside a 429; the existing drain path must not discard them.
func TestDoReqWithHeadersReturnsHeadersOnNon2xx(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"rate limited", 429},
		{"gateway timeout", 504},
		{"unauthorized", 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Flare-Global-Searches-Remaining", "42")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				// Plain-text body on an error response: decoding it would fail
				// and mask the status, which is why the drain path exists.
				_, _ = w.Write([]byte("upstream request timeout"))
			}))
			defer srv.Close()

			c := NewHTTPClientWithTimeOut(false, 10)
			target := map[string]bool{}

			status, hdr, err := c.DoReqWithHeaders(srv.URL, "GET", &target, nil, nil, nil)
			if err != nil {
				t.Fatalf("DoReqWithHeaders() error = %v, want nil (status is the signal)", err)
			}

			if status != tt.status {
				t.Errorf("status = %d, want %d", status, tt.status)
			}
			if got := hdr.Get("X-Flare-Global-Searches-Remaining"); got != "42" {
				t.Errorf("remaining header = %q, want %q on a %d", got, "42", tt.status)
			}
			if len(target) != 0 {
				t.Errorf("target = %v, want empty (error bodies must not be decoded)", target)
			}
		})
	}
}

// TestDoReqDelegationPreservesBehavior pins the promise that DoReq is unchanged
// for its existing callers now that it delegates.
func TestDoReqDelegationPreservesBehavior(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewHTTPClientWithTimeOut(false, 10)

	viaDoReq := map[string]bool{}
	status, err := c.DoReq(srv.URL, "GET", &viaDoReq, nil, nil, nil)
	if err != nil {
		t.Fatalf("DoReq() error = %v", err)
	}

	viaHeaders := map[string]bool{}
	statusWithHeaders, _, err := c.DoReqWithHeaders(srv.URL, "GET", &viaHeaders, nil, nil, nil)
	if err != nil {
		t.Fatalf("DoReqWithHeaders() error = %v", err)
	}

	if status != statusWithHeaders {
		t.Errorf("DoReq status = %d, DoReqWithHeaders status = %d; want identical", status, statusWithHeaders)
	}
	if viaDoReq["ok"] != viaHeaders["ok"] {
		t.Errorf("decoded targets differ: DoReq=%v, DoReqWithHeaders=%v", viaDoReq, viaHeaders)
	}
}

// TestDoReqWithHeadersStringTargetWritesFile covers the string-target branch
// used by the stealer-log file downloads.
func TestDoReqWithHeadersStringTargetWritesFile(t *testing.T) {
	const payload = "SOFT: Chrome\nUSER: someone\nPASS: hunter2\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "passwords.txt")
	c := NewHTTPClientWithTimeOut(false, 10)

	status, _, err := c.DoReqWithHeaders(srv.URL, "GET", outputPath, nil, nil, nil)
	if err != nil {
		t.Fatalf("DoReqWithHeaders() error = %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading %s: %v", outputPath, err)
	}
	if string(got) != payload {
		t.Errorf("file contents = %q, want %q", got, payload)
	}
}

func TestDoReqWithHeadersTransportFailureReturnsNilHeader(t *testing.T) {
	c := NewHTTPClientWithTimeOut(false, 1)

	// Port 0 on the loopback interface is never connectable.
	status, hdr, err := c.DoReqWithHeaders("http://127.0.0.1:0", "GET", nil, nil, nil, nil)

	if err == nil {
		t.Fatal("DoReqWithHeaders() error = nil, want a transport error")
	}
	if status != 0 {
		t.Errorf("status = %d, want 0 on a transport failure", status)
	}
	if hdr != nil {
		t.Errorf("header = %v, want nil on a transport failure", hdr)
	}
}

// TestDoReqWithHeadersKeepsExistingQuery matters because URLs returned by the
// API, such as an identity's links.next, carry their cursor in the query.
func TestDoReqWithHeadersKeepsExistingQuery(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewHTTPClientWithTimeOut(false, 10)

	if _, _, err := c.DoReqWithHeaders(srv.URL+"/next?from=WzFd%3D", "GET", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "from=WzFd%3D" {
		t.Errorf("query = %q, want the URL's own query untouched", gotQuery)
	}

	if _, _, err := c.DoReqWithHeaders(srv.URL+"/next?from=abc", "GET", nil, nil, map[string]string{"size": "10"}, nil); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "from=abc&size=10" {
		t.Errorf("query = %q, want params merged into the URL's query", gotQuery)
	}
}
