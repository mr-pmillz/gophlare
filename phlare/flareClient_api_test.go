package phlare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordedRequest is one request captured by fakeFlare.
type recordedRequest struct {
	Path          string
	Query         string
	Authorization string
	Body          string
}

// fakeFlare is an httptest server that answers /tokens/generate and delegates
// every other path to handle, recording each request.
type fakeFlare struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
	tokens   int
}

func newFakeFlare(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body string)) *fakeFlare {
	t.Helper()
	f := &fakeFlare{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(b)})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/tokens/generate" {
			f.mu.Lock()
			f.tokens++
			n := f.tokens
			f.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"token":"token-%d","refresh_token_exp":%d}`, n, time.Now().Add(24*time.Hour).Unix())
			return
		}
		handle(w, r, string(b))
	}))
	t.Cleanup(f.Close)
	return f
}

// apiRequests returns the recorded requests other than token generation.
func (f *fakeFlare) apiRequests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedRequest
	for _, r := range f.requests {
		if r.Path != "/tokens/generate" {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeFlare) tokenRequests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedRequest
	for _, r := range f.requests {
		if r.Path == "/tokens/generate" {
			out = append(out, r)
		}
	}
	return out
}

func TestTokenGenerateSendsRawAPIKeyAndTracksAPITokenLifetime(t *testing.T) {
	f := newFakeFlare(t, func(http.ResponseWriter, *http.Request, string) {})
	before := time.Now()
	fc, err := NewFlareClient("test-key", "", 42, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	req := f.tokenRequests()[0]
	if req.Authorization != "test-key" {
		t.Errorf("Authorization = %q, want the raw API key", req.Authorization)
	}
	if req.Body != `{"tenant_id":42}` {
		t.Errorf("body = %s", req.Body)
	}
	// The expiry must track the one-hour API token, not the day-long
	// refresh_token_exp the fake server returns.
	if fc.TokenExp.Before(before.Add(apiTokenLifetime)) || fc.TokenExp.After(time.Now().Add(apiTokenLifetime)) {
		t.Errorf("token expiry = %s, want about %s from now", fc.TokenExp, apiTokenLifetime)
	}

	if _, err := NewFlareClient("test-key", "", 0, 10, WithBaseURL(f.URL)); err != nil {
		t.Fatal(err)
	}
	if body := f.tokenRequests()[1].Body; body != `{}` {
		t.Errorf("default tenant body = %s, want tenant_id omitted", body)
	}
}

func TestRetrieveEventUsesUIDQueryAndDecodesStealerLog(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.URL.Path != "/firework/v2/activities/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"activity":{"data":{
			"uid":"stealer_log/stealer_logs/doc_2","id":"doc_2","index":"stealer_log","url":null,
			"installed_at":"2025-10-24T03:51:00+00:00",
			"metadata":{"first_crawled_at":"2025-10-28T18:35:15.095033+00:00","flare_url":"https://app.example.com/#/x"},
			"cookies":[{"host_key":".example.com","path":"/","expires_utc":"2026-03-04T02:22:08","name":"sid","value":"v"}],
			"credentials":[{"url":"https://example.com/login","username":"u@example.com","password":"p***","application":"Edge"}],
			"files":["Passwords.txt"],"sources":["stealer_logs_private"],
			"features":{"emails":["u@example.com"]}},
			"header":{"risk":{"score":3},"infection_date":"2025-10-24T03:51:00+00:00","contains_secrets":null},
			"metadata":{"scraped_at":"2025-10-28T18:35:17.333487+00:00"}}}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	data, err := fc.FlareRetrieveEventActivitiesByID("stealer_log/stealer_logs/doc_2")
	if err != nil {
		t.Fatal(err)
	}
	req := f.apiRequests()[0]
	if req.Query != "uid=stealer_log%2Fstealer_logs%2Fdoc_2" {
		t.Errorf("query = %q, want the UID as a query parameter", req.Query)
	}
	if req.Authorization != "Bearer token-1" {
		t.Errorf("Authorization = %q", req.Authorization)
	}
	d := data.Activity.Data
	if d.UID != "stealer_log/stealer_logs/doc_2" || d.Files[0] != "Passwords.txt" || d.Sources[0] != "stealer_logs_private" {
		t.Errorf("data = %+v", d)
	}
	if d.InstalledAt.Year() != 2025 || d.Metadata.FirstCrawledAt.IsZero() || d.Metadata.FlareURL == "" {
		t.Errorf("timestamps or metadata not decoded: %+v", d.Metadata)
	}
	if d.Cookies[0].ExpiresUtc != "2026-03-04T02:22:08" || d.Credentials[0].Username != "u@example.com" {
		t.Errorf("cookies or credentials not decoded: %+v %+v", d.Cookies, d.Credentials)
	}
	if data.Activity.Header.Risk.Score != 3 || data.Activity.Metadata.ScrapedAt.IsZero() {
		t.Errorf("header or activity metadata not decoded: %+v", data.Activity.Header)
	}
}

func TestSearchCredentialsASTPSendsNumericSizeAndPaginates(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, _ *http.Request, body string) {
		if strings.Contains(body, `"from":"page-2"`) {
			_, _ = w.Write([]byte(`{"items":[{"id":2,"identity_name":"b@example.com","domain":null,"hash":null,
				"imported_at":"2024-07-22T19:25:52.893439+00:00","source":null,"known_password_id":null}],"next":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"id":33880703907,"identity_name":"a@example.com","domain":"example.com",
			"hash":"B@dPassw0rd","hash_type":null,"imported_at":"2024-07-22T19:25:52.893439+00:00","source_id":"combolists",
			"source":{"id":"combolists","name":"Combolists","breached_at":"2019-01-07T21:59:00+00:00","leaked_at":null,"is_alert_enabled":true}}],
			"next":"page-2"}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	data, err := fc.FlareSearchCredentialsByDomainASTP("example.com")
	if err != nil {
		t.Fatal(err)
	}
	reqs := f.apiRequests()
	if len(reqs) != 2 || reqs[0].Path != "/astp/v2/credentials/_search" {
		t.Fatalf("requests = %+v", reqs)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(reqs[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if size, ok := body["size"].(float64); !ok || size != 100 {
		t.Errorf("size = %#v, want the number 100", body["size"])
	}
	query, _ := body["query"].(map[string]any)
	if query["type"] != "domain" || query["fqdn"] != "example.com" {
		t.Errorf("query = %#v", body["query"])
	}
	if len(data.Items) != 2 {
		t.Fatalf("items = %d, want 2 across both pages", len(data.Items))
	}
	first := data.Items[0]
	if first.ID != 33880703907 || first.Source.BreachedAt.Year() != 2019 || !first.Source.LeakedAt.IsZero() {
		t.Errorf("first credential = %+v", first)
	}
	if data.Items[1].Domain != "" || data.Items[1].Hash != "" {
		t.Errorf("null fields should decode to empty strings: %+v", data.Items[1])
	}
}

func TestPaginationRefreshesExpiredToken(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, _ *http.Request, body string) {
		if strings.Contains(body, `"from":"page-2"`) {
			_, _ = w.Write([]byte(`{"items":[],"next":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[],"next":"page-2"}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	fc.TokenExp = new(time.Now().Add(-time.Minute))
	if _, err := fc.FlareSearchCredentialsByDomainASTP("example.com"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.tokenRequests()); n != 2 {
		t.Fatalf("token requests = %d, want one refresh", n)
	}
	for _, r := range f.apiRequests() {
		if r.Authorization != "Bearer token-2" {
			t.Errorf("page used %q, want the refreshed token", r.Authorization)
		}
	}
	if *fc.Token != "token-2" {
		t.Errorf("client token = %q, want it refreshed in place", *fc.Token)
	}
}

func TestBulkCredentialLookupUsesASTPPath(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = w.Write([]byte(`{"hello":{"links":{},"name":"hello","passwords":[{"credential_hash":"4380","domain":null,
			"extra":{},"hash":"hello@bosslist.ru","hash_type":"unknown","id":4987562,"imported_at":"2019-06-03T14:20:25.132662+00:00",
			"source":{"breached_at":"2019-01-07T21:59:00+00:00","id":"collection-1","leaked_at":null,"url":null},
			"source_id":"collection-1","source_params":null}]}}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := fc.FlareBulkCredentialLookup([]string{"hello"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := f.apiRequests()[0]
	if req.Path != "/astp/identities/by_accounts" || req.Body != `{"accounts":["hello"]}` {
		t.Errorf("request = %+v", req)
	}
	pw := (*result)["hello"].Passwords[0]
	if pw.Domain != "" || pw.ImportedAt.Year() != 2019 || pw.Source.BreachedAt.IsZero() || !pw.Source.LeakedAt.IsZero() {
		t.Errorf("password = %+v", pw)
	}
}

func TestGlobalSearchRequestBody(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"uid":"stealer_log/x/1","type":"stealer_log","severity":"high",
			"estimated_created_at":"2019-09-20T16:30:37.589388Z","matched_at":null,"flare_url":"u"},
			"highlights":{"description":["a"]}}],"next":null}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	results, err := fc.FlareEventsGlobalSearchByDomain("example.com", t.TempDir(), "", "2025-01-01", "2025-02-01T12:00:00Z", []string{"high", "critical"}, []string{"stealer_log"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Query   map[string]string `json:"query"`
		Size    int               `json:"size"`
		Filters struct {
			Severity           []string          `json:"severity"`
			Type               []string          `json:"type"`
			EstimatedCreatedAt map[string]string `json:"estimated_created_at"`
		} `json:"filters"`
	}
	if err := json.Unmarshal([]byte(f.apiRequests()[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Query["type"] != "query_string" || body.Query["query_string"] != "metadata.source:stealer_logs* AND features.emails:*@example.com" {
		t.Errorf("query = %#v", body.Query)
	}
	if body.Size != DefaultGlobalSearchPageSize || strings.Join(body.Filters.Severity, ",") != "high,critical" || body.Filters.Type[0] != "stealer_log" {
		t.Errorf("body = %+v", body)
	}
	if body.Filters.EstimatedCreatedAt["gte"] != "2025-01-01T00:00:00Z" || body.Filters.EstimatedCreatedAt["lte"] != "2025-02-01T12:00:00Z" {
		t.Errorf("date filter = %#v", body.Filters.EstimatedCreatedAt)
	}
	item := results.Items[0]
	if string(item.Metadata.Type) != "stealer_log" || item.Metadata.UID != "stealer_log/x/1" || item.Highlights["description"][0] != "a" {
		t.Errorf("item = %+v", item)
	}

	if _, err := fc.FlareEventsGlobalSearchByDomain("example.com", t.TempDir(), "", "not-a-date", "", nil, nil, false, false); err == nil {
		t.Error("expected an error for an invalid from date")
	}
}

func TestSearchCookiesRequestBody(t *testing.T) {
	f := newFakeFlare(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = w.Write([]byte(`{"items":[{"uuid":"44672461","domain":"example.com","expires_at":"2024-10-18T00:00:00+00:00",
			"imported_at":"2024-01-01T00:00:00+00:00","name":"session","path":"/","event_uid":"stealer_log/x/1","value":"v"}],"next":null}`))
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	results, err := fc.FlareSearchCookiesByDomain("example.com", t.TempDir(), []string{"session"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(f.apiRequests()[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if body["domain"] != "example.com" || body["size"] != float64(500) || body["expires_after"] == nil {
		t.Errorf("body = %#v", body)
	}
	if _, ok := body["paths"]; ok {
		t.Errorf("empty paths should be omitted: %#v", body)
	}
	if c := results.Items[0]; c.UUID != "44672461" || c.ExpiresAt.Year() != 2024 || c.EventUID != "stealer_log/x/1" {
		t.Errorf("cookie = %+v", c)
	}
}
