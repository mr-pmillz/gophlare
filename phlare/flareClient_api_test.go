package phlare

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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
	if want := map[string]string{"gte": "2025-01-01T00:00:00Z", "lte": "2025-02-01T12:00:00Z"}; !maps.Equal(body.Filters.EstimatedCreatedAt, want) {
		t.Errorf("date filter = %#v, want %#v", body.Filters.EstimatedCreatedAt, want)
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

func TestSearchDateFilter(t *testing.T) {
	now := time.Date(2026, 9, 24, 15, 30, 0, 0, time.UTC)
	tests := []struct {
		name     string
		from, to string
		want     string
	}{
		{"date-only to covers that whole day", "2025-01-01", "2025-02-19",
			`{"gte":"2025-01-01T00:00:00Z","lt":"2025-02-20T00:00:00Z"}`},
		{"empty to covers all of today", "2025-01-01", "",
			`{"gte":"2025-01-01T00:00:00Z","lt":"2026-09-25T00:00:00Z"}`},
		{"timestamp to is inclusive", "2025-01-01T08:00:00Z", "2025-02-19T12:00:00Z",
			`{"gte":"2025-01-01T08:00:00Z","lte":"2025-02-19T12:00:00Z"}`},
		{"empty from searches the last 2 years", "", "2026-09-24",
			`{"gte":"2024-09-24T15:30:00Z","lt":"2026-09-25T00:00:00Z"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := searchDateFilter(tt.from, tt.to, now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(filter)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("filter = %s, want %s", got, tt.want)
			}
		})
	}
	for _, bad := range [][2]string{{"not-a-date", ""}, {"", "tomorrow"}} {
		if _, err := searchDateFilter(bad[0], bad[1], now); err == nil {
			t.Errorf("searchDateFilter(%q, %q) should fail", bad[0], bad[1])
		}
	}
}

// identityJSON renders a by_accounts identity with the given password IDs and
// next link.
func identityJSON(name, next string, ids ...int) string {
	passwords := make([]string, 0, len(ids))
	for _, id := range ids {
		passwords = append(passwords, fmt.Sprintf(`{"id":%d,"hash":"pw-%d","imported_at":"2019-06-03T14:20:25+00:00"}`, id, id))
	}
	links := `{}`
	if next != "" {
		links = fmt.Sprintf(`{"next":%q}`, next)
	}
	return fmt.Sprintf(`{"links":%s,"name":%q,"passwords":[%s]}`, links, name, strings.Join(passwords, ","))
}

func passwordIDs(e Entry) []int64 {
	ids := make([]int64, 0, len(e.Passwords))
	for _, p := range e.Passwords {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestBulkCredentialLookupFollowsIdentityNextLinks(t *testing.T) {
	var f *fakeFlare
	f = newFakeFlare(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		switch r.URL.Path {
		case "/astp/identities/by_accounts":
			// A relative link whose cursor lives in the query string.
			_, _ = fmt.Fprintf(w, `{"a@example.com":%s,"b@example.com":%s}`,
				identityJSON("a@example.com", "/leaksdb/identities/a@example.com/passwords?from=2", 1, 2),
				identityJSON("b@example.com", "", 9))
		case "/leaksdb/identities/a@example.com/passwords":
			if r.URL.Query().Get("from") == "2" {
				// An identity object whose next link is absolute.
				_, _ = w.Write([]byte(identityJSON("a@example.com", f.URL+"/leaksdb/identities/a@example.com/passwords?from=3", 3)))
				return
			}
			// A list of identities, the shape of the other /identities/ endpoints.
			_, _ = fmt.Fprintf(w, `[%s]`, identityJSON("a@example.com", "", 4))
		default:
			http.NotFound(w, r)
		}
	})
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := fc.FlareBulkCredentialLookup([]string{"a@example.com", "b@example.com"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := (*result)["a@example.com"]
	if got := passwordIDs(a); !slices.Equal(got, []int64{1, 2, 3, 4}) {
		t.Errorf("a@example.com passwords = %v, want all 4 pages", got)
	}
	if a.Links.Next != "" {
		t.Errorf("links.next = %q, want it cleared once every page was fetched", a.Links.Next)
	}
	if got := passwordIDs((*result)["b@example.com"]); !slices.Equal(got, []int64{9}) {
		t.Errorf("b@example.com passwords = %v", got)
	}
	reqs := f.apiRequests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %+v, want by_accounts plus 2 next pages", reqs)
	}
	for _, r := range reqs[1:] {
		if r.Authorization != "Bearer token-1" {
			t.Errorf("next page sent Authorization %q", r.Authorization)
		}
	}
	if reqs[1].Query != "from=2" || reqs[2].Query != "from=3" {
		t.Errorf("next page queries = %q, %q", reqs[1].Query, reqs[2].Query)
	}
}

func TestBulkCredentialLookupStopsOnUnsafeOrFailingNextLinks(t *testing.T) {
	tests := []struct {
		name      string
		next      string
		wantIDs   []int64
		wantPages int
	}{
		{"link to another host is never requested", "https://evil.example/steal", []int64{1}, 0},
		{"repeated link is fetched once", "/loop", []int64{1, 2}, 1},
		{"failed page keeps the passwords already fetched", "/missing", []int64{1}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeFlare(t, func(w http.ResponseWriter, r *http.Request, _ string) {
				switch r.URL.Path {
				case "/astp/identities/by_accounts":
					_, _ = fmt.Fprintf(w, `{"a@example.com":%s}`, identityJSON("a@example.com", tt.next, 1))
				case "/loop":
					_, _ = w.Write([]byte(identityJSON("a@example.com", "/loop", 2)))
				default:
					http.NotFound(w, r)
				}
			})
			fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(f.URL))
			if err != nil {
				t.Fatal(err)
			}
			result, err := fc.FlareBulkCredentialLookup([]string{"a@example.com"}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a := (*result)["a@example.com"]
			if got := passwordIDs(a); !slices.Equal(got, tt.wantIDs) {
				t.Errorf("passwords = %v, want %v", got, tt.wantIDs)
			}
			if pages := len(f.apiRequests()) - 1; pages != tt.wantPages {
				t.Errorf("next pages requested = %d, want %d", pages, tt.wantPages)
			}
			if a.Links.Next == "" {
				t.Error("links.next should still point at the pages that were not fetched")
			}
		})
	}
}
