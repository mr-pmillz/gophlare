package phlare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The ASTP credentials search deserializes `size` as an unsigned integer and
// rejects a JSON string with HTTP 422 ("invalid type: string, expected usize"),
// so size must marshal as a bare JSON number.
func TestCredentialsBodyParamsSizeSerializesAsNumber(t *testing.T) {
	body := &FlareSearchCredentialsBodyParams{
		Size:  100,
		Query: FlareDomainQuery{Type: "domain", Fqdn: "example.com"},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"size":100`) {
		t.Errorf(`size must serialize as a JSON number ("size":100), got: %s`, b)
	}
	if strings.Contains(string(b), `"size":"100"`) {
		t.Errorf(`size must not serialize as a string, got: %s`, b)
	}
}

func TestFlareSearchCredentialsByDomainASTPSendsNumericSize(t *testing.T) {
	var searchBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/tokens/generate" {
			_, _ = fmt.Fprintf(w, `{"token":"test-token","refresh_token_exp":%d}`, time.Now().Add(time.Hour).Unix())
			return
		}
		searchBody, _ = io.ReadAll(req.Body)
		_, _ = w.Write([]byte(`{"items":[],"next":null}`))
	}))
	defer srv.Close()

	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.FlareSearchCredentialsByDomainASTP("example.com"); err != nil {
		t.Fatal(err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(searchBody, &got); err != nil {
		t.Fatalf("decode request body %q: %v", searchBody, err)
	}
	var size uint
	if err := json.Unmarshal(got["size"], &size); err != nil {
		t.Fatalf("size must be a JSON unsigned integer, got %s: %v", got["size"], err)
	}
	if size != 100 {
		t.Fatalf("size = %d, want 100", size)
	}
}
