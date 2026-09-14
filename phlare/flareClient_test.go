package phlare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/gophlare/internal/version"
	"github.com/mr-pmillz/gophlare/metrics"
)

func TestClientUserAgentVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"test-token","refresh_token_exp":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer srv.Close()

	for _, userAgent := range []string{"", "custom-client/1.0"} {
		fc, err := NewFlareClient("test-key", userAgent, 1, 10, WithBaseURL(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		want := userAgent
		if want == "" {
			want = "gophlare/" + version.String()
		}
		if fc.DefaultUserAgent != want {
			t.Errorf("user-agent = %q, want %q", fc.DefaultUserAgent, want)
		}
	}
}

func TestClientRecordsAuthPaginationRetriesAndEntity(t *testing.T) {
	var attempts atomic.Int32
	var pageSizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/tokens/generate" {
			_, _ = fmt.Fprintf(w, `{"token":"test-token","refresh_token_exp":%d}`, time.Now().Add(time.Hour).Unix())
			return
		}
		var body FlareEventsGlobalSearchBodyParams
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		pageSizes = append(pageSizes, body.Size)
		switch attempts.Add(1) {
		case 1:
			w.Header().Set(metrics.HeaderGlobalSearchesRemaining, "9999")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.Header().Set(metrics.HeaderGlobalSearchesRemaining, "9999")
			_, _ = w.Write([]byte(`{"items":[],"next":"page-2"}`))
		default:
			if body.From != "page-2" {
				t.Errorf("cursor = %q", body.From)
			}
			w.Header().Set(metrics.HeaderGlobalSearchesRemaining, "9998")
			_, _ = w.Write([]byte(`{"items":[],"next":null}`))
		}
	}))
	defer srv.Close()
	recorder := metrics.NewRecorder()
	fc, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(srv.URL), WithMetricsRecorder(recorder), WithGlobalSearchPageSize(10))
	if err != nil {
		t.Fatal(err)
	}
	scoped := fc.ForEntity(metrics.EntityCustomQuery)
	if _, err := scoped.FlareEventsGlobalSearchByDomain("", t.TempDir(), "test-query", "", "", nil, nil, false, false); err != nil {
		t.Fatal(err)
	}
	s := recorder.Snapshot(10000)
	if fc.Entity != "" || s.Totals.Calls != 4 || s.Totals.Retries != 1 || s.Totals.RateLimited != 1 {
		t.Fatalf("attribution or attempt counters incorrect: %+v", s)
	}
	if s.ObservedConsumed == nil || *s.ObservedConsumed != 1 {
		t.Fatalf("unexpected delta: %+v", s)
	}
	for _, entity := range s.ByEntity {
		if entity.Entity == metrics.EntityCustomQuery && entity.Calls != 3 {
			t.Fatalf("query attribution: %+v", entity)
		}
	}
	for _, size := range pageSizes {
		if size != 10 {
			t.Fatalf("page size = %d", size)
		}
	}
}

func TestRefreshPreservesMetricsAndConfiguration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"fresh-token","refresh_token_exp":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer srv.Close()
	r := metrics.NewRecorder()
	fc, err := NewFlareClient("test-key", "test-agent", 1, 10, WithBaseURL(srv.URL), WithMetricsRecorder(r), WithGlobalSearchPageSize(10), WithEntity("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	fc.TokenExp = new(time.Now().Add(-time.Hour))
	refreshed, err := fc.RefreshAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Metrics != r || refreshed.Entity != "example.com" || refreshed.BaseURL != srv.URL || refreshed.pageSize() != 10 {
		t.Fatalf("refresh dropped configuration: %+v", refreshed)
	}
	if s := r.Snapshot(0); s.Totals.Calls != 2 || len(s.ByEntity) != 1 || s.ByEntity[0].Entity != metrics.EntityAuth {
		t.Fatalf("auth metrics = %+v", s)
	}
}

func TestInvalidPageSizeDoesNotAuthenticate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	if _, err := NewFlareClient("test-key", "", 1, 10, WithBaseURL(srv.URL), WithGlobalSearchPageSize(11)); err == nil {
		t.Fatal("expected page size error")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid options made an API request")
	}
}

func TestSearchRetriesAreBounded(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503, 504} {
		for retry := range maxSearchRetries {
			if delay, err := searchRetryDelay(status, retry); err != nil || delay <= 0 {
				t.Fatalf("retry %d: %s, %v", retry, delay, err)
			}
		}
		if _, err := searchRetryDelay(status, maxSearchRetries); err == nil {
			t.Fatalf("status %d retries forever", status)
		}
	}
	if delay, err := searchRetryDelay(200, maxSearchRetries); err != nil || delay != 0 {
		t.Fatalf("success retried: %v", err)
	}
}

func TestClientBaseURLDefaultsAndNormalization(t *testing.T) {
	fc := &FlareClient{}
	if fc.baseURL() != flareAPIBaseURL {
		t.Fatalf("base URL = %q", fc.baseURL())
	}
	WithBaseURL("http://example.test/")(fc)
	if fc.baseURL() != "http://example.test" {
		t.Fatalf("base URL = %q", fc.baseURL())
	}
}
