# Flare API Query Metrics Implementation Plan

> Review correction: quota header differences cover an incomplete organization-wide
> interval, not total run spend. Single observations and quota increases yield
> unknown consumption. Page size reduces requests, with no guaranteed quota savings.
> The CLI now reports from resolved options with a recorder per invocation.
> See the README for current behavior; the design below records the original plan.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--metrics` flag that reports how many Flare API calls a run made, how many of them billed against the monthly Global Search quota, and how much quota remains — broken out per endpoint and per entity.

**Architecture:** A new dependency-free `metrics` package owns a mutex-guarded `Recorder`, an endpoint→quota classification catalog, and a `text/tabwriter` report renderer. `phlare.Client` gains `DoReqWithHeaders` so the authoritative `X-Flare-Global-Searches-Remaining` response header stops being discarded; `DoReq` delegates to it and is behaviorally unchanged. Each `FlareClient` method records its own call, because it alone knows both its endpoint and its domain.

**Tech Stack:** Go 1.26, cobra/viper, `text/tabwriter` + `fatih/color` (both already available), `net/http/httptest`. **No new module dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-10-flare-api-metrics-design.md`

## Global Constraints

- **No new dependencies.** `go.mod` must be unchanged except by `go mod tidy` no-ops.
- **`--global-search-page-size` defaults to `5`.** This was deliberately reduced from 10; the default must not change. The flag only lets an operator opt into something else.
- **`--monthly-quota` defaults to `10000`**, and the report must label it as operator-supplied — Flare documents quota as license-dependent.
- **`/leaksdb/identities/by_accounts` quota billing is undocumented** and must render as `?`, never `yes` or `no`.
- **Observed beats counted.** Where the header-derived number and the local counter disagree, the report presents observed as authoritative and explains the gap.
- **`DoReq`'s existing signature and behavior are frozen** — `bloodhound/api.go:60` and external SDK consumers call it. Same for the four exported `FlareClient` search/download method signatures.
- **`NewFlareClient` stays backward compatible** via variadic `...ClientOption`.
- Lint gates: `gocognit`, `dupl`, `goconst`, `gocritic`, `gosec`, `errorlint`, `staticcheck`, `whitespace`. Run `make lint`.
- Version constant appears in **both** `cmd/root.go` and `phlare/flareClient.go` and must be bumped together.
- Tests are table-driven and must pass under `-race`.

---

### Task 1: `metrics` endpoint catalog

**Files:**
- Create: `metrics/endpoints.go`
- Test: `metrics/endpoints_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Endpoint` (string type) with constants `EndpointTokenGenerate`, `EndpointGlobalEventsSearch`, `EndpointActivityByID`, `EndpointActivityDownload`, `EndpointActivityDownloadFile`, `EndpointASTPCredentialsSearch`, `EndpointASTPCookiesSearch`, `EndpointBulkAccounts`; `QuotaClass` with `QuotaNo`/`QuotaYes`/`QuotaUnknown` and a `String()` returning `"no"`/`"yes"`/`"?"`; `RateLimitTier` with `TierBasic`/`TierSearch`; `EndpointInfo{Endpoint, Quota, Tier}`; `Lookup(Endpoint) EndpointInfo`; `KnownEndpoints() []Endpoint` (sorted); entity constants `EntityAuth = "auth"`, `EntityBulkEmails = "bulk-emails"`, `EntityCustomQuery = "custom-query"`, `EntityUnattributed = "-"`; `DefaultMonthlyQuota = 10000`; header name constants `HeaderGlobalSearchesRemaining = "X-Flare-Global-Searches-Remaining"` and `HeaderGlobalSearchesBatchReached = "X-Flare-Global-Searches-Batch-Reached"`.

- [ ] **Step 1: Write the failing test**

```go
func TestLookupQuotaClass(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		want     QuotaClass
		wantStr  string
	}{
		{"global events search bills quota", EndpointGlobalEventsSearch, QuotaYes, "yes"},
		{"astp credentials search does not bill", EndpointASTPCredentialsSearch, QuotaNo, "no"},
		{"bulk accounts billing is undocumented", EndpointBulkAccounts, QuotaUnknown, "?"},
		{"unregistered endpoint is unknown", Endpoint("/nope"), QuotaUnknown, "?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Lookup(tt.endpoint)
			if got.Quota != tt.want {
				t.Errorf("Lookup(%q).Quota = %v, want %v", tt.endpoint, got.Quota, tt.want)
			}
			if got.Quota.String() != tt.wantStr {
				t.Errorf("Quota.String() = %q, want %q", got.Quota.String(), tt.wantStr)
			}
		})
	}
}
```

Also assert `KnownEndpoints()` is sorted and has 8 entries, and that global/ASTP searches are `TierSearch` while activities are `TierBasic`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./metrics/... -run TestLookup -v`
Expected: FAIL — `undefined: Lookup`.

- [ ] **Step 3: Write minimal implementation**

`Endpoint` values are path templates (`/firework/v2/activities/{uid}`) so all activity calls collapse to one report row. `endpointCatalog` is a package-level `map[Endpoint]EndpointInfo`; `Lookup` returns `EndpointInfo{Endpoint: e, Quota: QuotaUnknown, Tier: TierBasic}` for a miss. `KnownEndpoints` returns catalog keys sorted with `sort.Slice`.

- [ ] **Step 4: Run tests**

Run: `go test ./metrics/... -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add metrics/endpoints.go metrics/endpoints_test.go
git commit -m "feat(metrics): add Flare endpoint quota classification catalog"
```

---

### Task 2: `Recorder` and `Snapshot`

**Files:**
- Create: `metrics/metrics.go`
- Test: `metrics/metrics_test.go`

**Interfaces:**
- Consumes: Task 1's `Endpoint`, `QuotaClass`, `Lookup`, header constants.
- Produces:
  - `Call{Endpoint Endpoint; Entity string; Status int; Duration time.Duration; Header http.Header; Retry bool}`
  - `NewRecorder() *Recorder`, `Default() *Recorder`
  - `(*Recorder).Record(Call)` — safe on a nil receiver and safe for concurrent use
  - `(*Recorder).Snapshot(monthlyQuota int) Snapshot`
  - `EndpointStat{Endpoint, Quota, Tier string; Calls, OK, RateLimited, ServerError, Retries int; QuotaUnits int; AvgDuration time.Duration}` where `QuotaUnits` is `-1` for an unknown-billing endpoint
  - `EntityStat{Entity string; Calls, QuotaUnits int; QuotaUnknown bool; ByEndpoint []EndpointStat}`
  - `Snapshot{GeneratedAt time.Time; Duration time.Duration; MonthlyQuota int; QuotaHeaderSeen bool; RemainingFirst, RemainingLast *int; ObservedConsumed *int; CountedQuotaCalls int; BatchReached int; ByEndpoint []EndpointStat; ByEntity []EntityStat; Totals EndpointStat}`

- [ ] **Step 1: Write the failing test**

```go
func TestRecorderObservedConsumedFromHeaderDelta(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200,
		Header: http.Header{HeaderGlobalSearchesRemaining: []string{"9000"}}})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200,
		Header: http.Header{HeaderGlobalSearchesRemaining: []string{"8998"}}})

	s := r.Snapshot(10000)
	if !s.QuotaHeaderSeen {
		t.Fatal("QuotaHeaderSeen = false, want true")
	}
	if s.ObservedConsumed == nil || *s.ObservedConsumed != 2 {
		t.Errorf("ObservedConsumed = %v, want 2", s.ObservedConsumed)
	}
	if s.RemainingLast == nil || *s.RemainingLast != 8998 {
		t.Errorf("RemainingLast = %v, want 8998", s.RemainingLast)
	}
	if s.CountedQuotaCalls != 2 {
		t.Errorf("CountedQuotaCalls = %d, want 2", s.CountedQuotaCalls)
	}
}
```

Additional cases in the same file:
- `nil` recorder: `var r *Recorder; r.Record(Call{...})` must not panic.
- No header ever seen → `QuotaHeaderSeen == false`, `ObservedConsumed == nil`.
- Malformed header (`"banana"`, `""`) → ignored, `QuotaHeaderSeen` stays false.
- Status classification: `200`→OK, `429`→RateLimited, `503`→ServerError, `404`→neither OK nor error buckets but still counted in `Calls`.
- `Retry: true` increments `Retries`.
- `X-Flare-Global-Searches-Batch-Reached` present → `BatchReached` increments.
- `QuotaUnits` is `-1` for `EndpointBulkAccounts`, equals `Calls` for `EndpointGlobalEventsSearch`, `0` for `EndpointASTPCredentialsSearch`.
- Entity `""` normalizes to `EntityUnattributed`.
- `ByEndpoint` and `ByEntity` are sorted by name; `ByEntity[i].ByEndpoint` sorted too.
- `AvgDuration` = total/calls.
- Concurrency: 100 goroutines × 100 `Record` calls, then assert `Totals.Calls == 10000`. Must pass `-race`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./metrics/... -run TestRecorder -v`
Expected: FAIL — `undefined: NewRecorder`.

- [ ] **Step 3: Write minimal implementation**

Internal state keyed by `struct{endpoint Endpoint; entity string}` → `*counters{Calls, OK, RateLimited, ServerError, Retries int; Total time.Duration}`. Header parsing helper:

```go
// noteQuotaHeaders extracts Flare's quota headers. A missing or unparseable
// value is ignored rather than treated as zero: reporting "0 remaining"
// because a header was absent would be worse than reporting nothing.
func (r *Recorder) noteQuotaHeaders(h http.Header) {
	if h == nil {
		return
	}
	if raw := h.Get(HeaderGlobalSearchesRemaining); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			if !r.quotaHeaderSeen {
				r.quotaHeaderSeen = true
				first := n
				r.firstRemaining = &first
			}
			last := n
			r.lastRemaining = &last
		}
	}
	if h.Get(HeaderGlobalSearchesBatchReached) != "" {
		r.batchReached++
	}
}
```

`Record` locks, calls `noteQuotaHeaders`, then increments. `Snapshot` locks, aggregates, sorts, and computes `ObservedConsumed = *firstRemaining - *lastRemaining` only when both are non-nil.

- [ ] **Step 4: Run tests**

Run: `go test ./metrics/... -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add metrics/metrics.go metrics/metrics_test.go
git commit -m "feat(metrics): add concurrency-safe API usage recorder"
```

---

### Task 3: Report rendering, JSON output, `ReportOnce`

**Files:**
- Create: `metrics/report.go`
- Test: `metrics/report_test.go`

**Interfaces:**
- Consumes: Task 2's `Snapshot`, `Recorder`.
- Produces: `ReportOptions{Enabled bool; MonthlyQuota int; OutputDir string; Version string; Writer io.Writer; Colorize bool}`; `(Snapshot).Render(w io.Writer, colorize bool) error`; `WriteJSON(Snapshot, path string) error`; `(*Recorder).ReportOnce(ReportOptions) error`.

- [ ] **Step 1: Write the failing test**

```go
func TestRenderShowsUnknownQuotaAsQuestionMark(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointBulkAccounts, Entity: EntityBulkEmails, Status: 200})

	var buf bytes.Buffer
	if err := r.Snapshot(10000).Render(&buf, false); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "/leaksdb/identities/by_accounts") {
		t.Errorf("report missing endpoint row:\n%s", out)
	}
	if strings.Contains(out, "by_accounts") && !regexp.MustCompile(`by_accounts\s+\?`).MatchString(out) {
		t.Errorf("bulk accounts billing should render as ?, got:\n%s", out)
	}
}

func TestReportOnceIsIdempotent(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	var buf bytes.Buffer
	opts := ReportOptions{Enabled: true, MonthlyQuota: 10000, Writer: &buf, Version: "v0.0.0-test"}
	if err := r.ReportOnce(opts); err != nil {
		t.Fatalf("first ReportOnce() error = %v", err)
	}
	first := buf.Len()
	if err := r.ReportOnce(opts); err != nil {
		t.Fatalf("second ReportOnce() error = %v", err)
	}
	if buf.Len() != first {
		t.Errorf("second ReportOnce wrote %d extra bytes, want 0", buf.Len()-first)
	}
}
```

Additional cases:
- `Enabled: false` writes nothing and returns nil.
- No quota-bearing calls → output contains a "no global searches" style line, and **must not** contain a bogus `Remaining` figure.
- Counted > observed → output contains the explanatory note mentioning the 10-minute window.
- `WriteJSON` to a temp dir round-trips through `json.Unmarshal` into `Snapshot` with `Totals.Calls` preserved.
- `ReportOptions.OutputDir == ""` → skips the file, still renders.
- `Render` output for a fixed snapshot matches a golden string (deterministic ordering).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./metrics/... -run 'TestRender|TestReportOnce' -v`
Expected: FAIL — `undefined: ReportOptions`.

- [ ] **Step 3: Write minimal implementation**

Three `tabwriter.Writer` blocks (quota summary, by endpoint, by entity). `QuotaUnits == -1` renders `?`; `0` on a non-billing endpoint renders `—`. Entity rows print the entity name only on its first endpoint row. `ReportOnce` uses a `sync.Once` field on `Recorder`, defaults `Writer` to `os.Stdout` and `MonthlyQuota` to `DefaultMonthlyQuota` when zero, renders, then writes `filepath.Join(OutputDir, "flare-api-metrics.json")` when `OutputDir != ""`. `WriteJSON` uses `os.WriteFile` with `0600` and `json.MarshalIndent`.

- [ ] **Step 4: Run tests**

Run: `go test ./metrics/... -race -v && go vet ./metrics/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add metrics/report.go metrics/report_test.go
git commit -m "feat(metrics): render usage report table and JSON artifact"
```

---

### Task 4: Surface response headers from the HTTP layer

**Files:**
- Modify: `phlare/http.go:36-79`
- Test: `phlare/http_test.go` (create)

**Interfaces:**
- Consumes: nothing new.
- Produces: `(Client).DoReqWithHeaders(u, method string, target interface{}, headers, params map[string]string, body []byte) (int, http.Header, error)`. `DoReq` keeps its exact signature and delegates.

- [ ] **Step 1: Write the failing test**

```go
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
		t.Error("body was not decoded into target")
	}
}
```

Additional cases:
- **Headers are returned on a 429**, and the body is not decoded (the existing non-2xx drain path).
- `DoReq` on the same server returns the identical status and decodes identically — proves delegation preserved behavior.
- String `target` still writes the body to that file path.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./phlare/... -run TestDoReq -v`
Expected: FAIL — `c.DoReqWithHeaders undefined`.

- [ ] **Step 3: Write minimal implementation**

Rename the existing body to `DoReqWithHeaders`, returning `resp.Header` alongside the status (including on the non-2xx drain path, and `nil` on transport errors). Then:

```go
// DoReq performs a request and returns only the status code. It is retained
// with its original signature because external callers depend on it; use
// DoReqWithHeaders when response headers matter.
func (c Client) DoReq(u, method string, target interface{}, headers map[string]string, params map[string]string, body []byte) (int, error) {
	statusCode, _, err := c.DoReqWithHeaders(u, method, target, headers, params, body)
	return statusCode, err
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./phlare/... -race -v && go build ./...`
Expected: PASS; `bloodhound/api.go` still compiles untouched.

- [ ] **Step 5: Commit**

```bash
git add phlare/http.go phlare/http_test.go
git commit -m "feat(phlare): add DoReqWithHeaders to expose response headers"
```

---

### Task 5: Client options, `BaseURL`, `ForEntity`, refresh passthrough

**Files:**
- Modify: `phlare/types.go:5-13` (the `FlareClient` struct)
- Modify: `phlare/flareClient.go:13-18` (consts), `21-71` (`NewFlareClient`), `82-92` (`RefreshAPIToken`)
- Test: `phlare/flareClient_test.go` (create — this file has no tests today)

**Interfaces:**
- Consumes: Task 2's `metrics.Recorder`, Task 1's `metrics.Endpoint`; Task 4's `DoReqWithHeaders`.
- Produces: `FlareClient` fields `BaseURL string`, `Metrics *metrics.Recorder`, `Entity string`, `GlobalSearchPageSize int`; `DefaultGlobalSearchPageSize = 5`; `type ClientOption func(*FlareClient)`; `WithMetricsRecorder(*metrics.Recorder) ClientOption`, `WithBaseURL(string) ClientOption`, `WithGlobalSearchPageSize(int) ClientOption`, `WithEntity(string) ClientOption`; `NewFlareClient(apiKey, userAgent string, tenantID, timeout int, opts ...ClientOption) (*FlareClient, error)`; `(*FlareClient).ForEntity(string) *FlareClient`; unexported `(*FlareClient).record(endpoint metrics.Endpoint, entity string, status int, hdr http.Header, started time.Time, retry bool)`.

- [ ] **Step 1: Write the failing test**

```go
// newTestFlareClient stands up a fake Flare API that serves /tokens/generate
// plus whatever the caller's handler covers, and returns a client pointed at it.
func newTestFlareClient(t *testing.T, rec *metrics.Recorder, h http.HandlerFunc) (*FlareClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokens/generate" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"test-token","refresh_token_exp":4102444800}`))
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	fc, err := NewFlareClient("test-key", "gophlare-test", 1, 10,
		WithBaseURL(srv.URL), WithMetricsRecorder(rec))
	if err != nil {
		t.Fatalf("NewFlareClient() error = %v", err)
	}
	return fc, srv
}

func TestForEntityDoesNotMutateReceiver(t *testing.T) {
	fc, _ := newTestFlareClient(t, metrics.NewRecorder(), func(w http.ResponseWriter, _ *http.Request) {})
	scoped := fc.ForEntity("example.com")
	if fc.Entity != "" {
		t.Errorf("receiver Entity = %q, want empty (ForEntity must not mutate)", fc.Entity)
	}
	if scoped.Entity != "example.com" {
		t.Errorf("scoped Entity = %q, want example.com", scoped.Entity)
	}
	if scoped.Client != fc.Client || scoped.Metrics != fc.Metrics {
		t.Error("ForEntity must share the underlying Client and Recorder")
	}
}

func TestRefreshAPITokenPreservesRecorderAndOptions(t *testing.T) {
	rec := metrics.NewRecorder()
	fc, srv := newTestFlareClient(t, rec, func(w http.ResponseWriter, _ *http.Request) {})

	expired := time.Now().Add(-time.Hour)
	fc.TokenExp = &expired
	refreshed, err := fc.RefreshAPIToken()
	if err != nil {
		t.Fatalf("RefreshAPIToken() error = %v", err)
	}
	if refreshed.Metrics != rec {
		t.Error("recorder lost across token refresh — counters would silently reset mid-run")
	}
	if refreshed.BaseURL != srv.URL {
		t.Errorf("BaseURL = %q, want %q", refreshed.BaseURL, srv.URL)
	}
	if refreshed.GlobalSearchPageSize != DefaultGlobalSearchPageSize {
		t.Errorf("page size = %d, want %d", refreshed.GlobalSearchPageSize, DefaultGlobalSearchPageSize)
	}
}

func TestDefaultGlobalSearchPageSizeIsFive(t *testing.T) {
	if DefaultGlobalSearchPageSize != 5 {
		t.Fatalf("DefaultGlobalSearchPageSize = %d, want 5 (deliberately reduced from 10)", DefaultGlobalSearchPageSize)
	}
}
```

Also assert the `/tokens/generate` call is recorded under `metrics.EntityAuth`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./phlare/... -run 'TestForEntity|TestRefresh|TestDefaultGlobal' -v`
Expected: FAIL — `undefined: WithBaseURL`.

- [ ] **Step 3: Write minimal implementation**

`NewFlareClient` builds a provisional `*FlareClient` with defaults (`BaseURL: flareAPIBaseURL`, `GlobalSearchPageSize: DefaultGlobalSearchPageSize`), applies `opts` **before** the token request so `WithBaseURL`/`WithMetricsRecorder` cover `/tokens/generate`, then performs the token request via `DoReqWithHeaders` and records it as `EndpointTokenGenerate` / `EntityAuth`. `RefreshAPIToken` forwards `WithBaseURL(fc.BaseURL)`, `WithMetricsRecorder(fc.Metrics)`, `WithGlobalSearchPageSize(fc.GlobalSearchPageSize)`, `WithEntity(fc.Entity)`.

```go
// record attributes one completed request to the recorder. A nil recorder is a
// no-op so SDK consumers who never opt in pay nothing.
func (fc *FlareClient) record(endpoint metrics.Endpoint, entity string, status int, hdr http.Header, started time.Time, retry bool) {
	if fc == nil || fc.Metrics == nil {
		return
	}
	if entity == "" {
		entity = fc.Entity
	}
	fc.Metrics.Record(metrics.Call{
		Endpoint: endpoint, Entity: entity, Status: status,
		Duration: time.Since(started), Header: hdr, Retry: retry,
	})
}
```

If `NewFlareClient` trips `gocognit`, add `//nolint:gocognit` per the existing convention on `LoadFromCommand`.

- [ ] **Step 4: Run tests**

Run: `go test ./phlare/... -race -v && make lint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add phlare/types.go phlare/flareClient.go phlare/flareClient_test.go
git commit -m "feat(phlare): add client options, overridable BaseURL, and entity scoping"
```

---

### Task 6: Instrument every Flare API call site

**Files:**
- Modify: `phlare/flareClient.go` — call sites at lines `121`, `167`, `219`, `262`, `363`, `479`, `554`, `656`; page size at `295`
- Test: `phlare/flareClient_test.go` (extend)

**Interfaces:**
- Consumes: Task 5's `record`, `ForEntity`, `GlobalSearchPageSize`; Task 1's endpoint constants.
- Produces: no new exported API. All eight `DoReq` calls become `DoReqWithHeaders` followed by `fc.record(...)`.

- [ ] **Step 1: Write the failing test**

```go
func TestGlobalSearchRecordsEveryPageAndRetries(t *testing.T) {
	rec := metrics.NewRecorder()
	var calls int
	fc, _ := newTestFlareClient(t, rec, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/firework/v4/events/global/_search" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			w.Header().Set("X-Flare-Global-Searches-Remaining", "9000")
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"uid":"a","type":"stealer_log"}}],"next":"cursor-1"}`))
		case 2:
			w.WriteHeader(429) // exercises the 10s-sleep retry path
		default:
			w.Header().Set("X-Flare-Global-Searches-Remaining", "8998")
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"uid":"b","type":"stealer_log"}}]}`))
		}
	})

	dir := t.TempDir()
	if _, err := fc.ForEntity("example.com").FlareEventsGlobalSearchByDomain(
		"example.com", dir, "", "", "", nil, nil, false, false); err != nil {
		t.Fatalf("FlareEventsGlobalSearchByDomain() error = %v", err)
	}

	s := rec.Snapshot(10000)
	var got metrics.EndpointStat
	for _, e := range s.ByEndpoint {
		if e.Endpoint == string(metrics.EndpointGlobalEventsSearch) {
			got = e
		}
	}
	if got.Calls != 3 {
		t.Errorf("Calls = %d, want 3 (two pages + one 429)", got.Calls)
	}
	if got.RateLimited != 1 {
		t.Errorf("RateLimited = %d, want 1", got.RateLimited)
	}
	if got.Retries != 1 {
		t.Errorf("Retries = %d, want 1", got.Retries)
	}
	if s.ObservedConsumed == nil || *s.ObservedConsumed != 2 {
		t.Errorf("ObservedConsumed = %v, want 2", s.ObservedConsumed)
	}
	if len(s.ByEntity) != 1 || s.ByEntity[0].Entity != "example.com" {
		t.Errorf("ByEntity = %+v, want a single example.com row", s.ByEntity)
	}
}
```

> This test sleeps ~10s inside the existing 429 branch. Guard it with
> `if testing.Short() { t.Skip("429 retry path sleeps 10s") }` so `go test -short` stays fast.

Additional cases:
- `FlareSearchCredentialsByDomainASTP` records under `EndpointASTPCredentialsSearch` with `QuotaUnits == 0`.
- `FlareRetrieveEventActivitiesByID` inherits `fc.Entity` (it has no domain parameter).
- `WithGlobalSearchPageSize(10)` puts `"size":10` in the request body; the default puts `"size":5`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./phlare/... -run TestGlobalSearchRecords -v`
Expected: FAIL — recorded `Calls` is 0.

- [ ] **Step 3: Write minimal implementation**

At each call site: capture `started := time.Now()`, swap `DoReq` → `DoReqWithHeaders`, call `fc.record(...)`. In the three pagination loops, track retry state so the retried attempt is flagged:

```go
retrying := false
flarePaginate:
	for {
		// ...
		started := time.Now()
		statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGlobalEventsSearchURL, "POST", data, headers, nil, postBodyJSON)
		fc.record(metrics.EndpointGlobalEventsSearch, domain, statusCode, respHeader, started, retrying)
		retrying = false
		if err != nil {
			return nil, utils.LogError(err)
		}
		if statusCode == 429 {
			retrying = true
			time.Sleep(10 * time.Second)
			continue
		}
		// ... same for the 500/502/503/504 branch
	}
```

Replace `size := 5` with `size := fc.GlobalSearchPageSize` plus a zero-guard falling back to `DefaultGlobalSearchPageSize` (a zero-valued `FlareClient` built by an SDK consumer without the constructor must not request `"size":0`).

Keep the `//nolint:dupl` directives — the three loops stay near-identical by design.

- [ ] **Step 4: Run tests**

Run: `go test ./phlare/... -race -v && make lint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add phlare/flareClient.go phlare/flareClient_test.go
git commit -m "feat(phlare): record usage metrics for every Flare API call"
```

---

### Task 7: Flags on `phlare.Options`

**Files:**
- Modify: `phlare/options.go:14-40` (struct), `48-78` (`ConfigureCommand`), `377-390` (`LoadFromCommand` integers)
- Test: `phlare/options_test.go` (extend)

**Interfaces:**
- Consumes: Task 1's `metrics.DefaultMonthlyQuota`; Task 5's `DefaultGlobalSearchPageSize`.
- Produces: `Options.Metrics bool`, `Options.MonthlyQuota int`, `Options.GlobalSearchPageSize int`.

- [ ] **Step 1: Write the failing test**

```go
func TestLoadFromCommandMetricsFlags(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantMetrics  bool
		wantQuota    int
		wantPageSize int
	}{
		{"defaults", nil, false, 10000, 5},
		{"metrics enabled", []string{"--metrics"}, true, 10000, 5},
		{"custom quota and page size",
			[]string{"--metrics", "--monthly-quota", "25000", "--global-search-page-size", "10"},
			true, 25000, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
			if err := ConfigureCommand(cmd); err != nil {
				t.Fatalf("ConfigureCommand() error = %v", err)
			}
			cmd.SetArgs(append([]string{"--output", t.TempDir()}, tt.args...))
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			opts := &Options{}
			if err := opts.LoadFromCommand(cmd); err != nil {
				t.Fatalf("LoadFromCommand() error = %v", err)
			}
			if opts.Metrics != tt.wantMetrics {
				t.Errorf("Metrics = %v, want %v", opts.Metrics, tt.wantMetrics)
			}
			if opts.MonthlyQuota != tt.wantQuota {
				t.Errorf("MonthlyQuota = %d, want %d", opts.MonthlyQuota, tt.wantQuota)
			}
			if opts.GlobalSearchPageSize != tt.wantPageSize {
				t.Errorf("GlobalSearchPageSize = %d, want %d", opts.GlobalSearchPageSize, tt.wantPageSize)
			}
		})
	}
}
```

Match the existing helper style in `phlare/options_test.go`; if that file already has a command-construction helper, reuse it rather than duplicating.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./phlare/... -run TestLoadFromCommandMetrics -v`
Expected: FAIL — `opts.Metrics undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
cmd.PersistentFlags().BoolP("metrics", "", false, "print a Flare API usage and quota report at the end of the run")
cmd.PersistentFlags().IntP("monthly-quota", "", metrics.DefaultMonthlyQuota, "your Flare monthly Global Search quota, used to calculate the percentage consumed in the --metrics report")
cmd.PersistentFlags().IntP("global-search-page-size", "", DefaultGlobalSearchPageSize, "number of events per global search request (size). Larger pages consume less quota but are likelier to hit Flare's gateway timeout")
```

Read them in `LoadFromCommand` beside the existing `GetBool`/`GetInt` blocks.

- [ ] **Step 4: Run tests**

Run: `go test ./phlare/... -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add phlare/options.go phlare/options_test.go
git commit -m "feat(phlare): add --metrics, --monthly-quota, and --global-search-page-size flags"
```

---

### Task 8: Wire the CLI

**Files:**
- Modify: `cmd/search/search.go:51`, `:59`, `:87-90`, `:101`, `:470`, `:486`, `:762`, `:773`
- Modify: `cmd/search/command.go:47-95` (the `Run` body)
- Modify: `cmd/root.go:29-44`

**Interfaces:**
- Consumes: Tasks 3, 5, 6, 7.
- Produces: unexported `reportMetrics(*phlare.Options)` and `fatalf(*phlare.Options, string, ...interface{})` in `cmd/search`; `RootCmd.PersistentPostRun`.

- [ ] **Step 1: Write the failing test**

```go
func TestFatalfHelperReportsBeforeExiting(t *testing.T) {
	// fatalf calls gologger.Fatal (os.Exit), so exercise the reporting half only.
	rec := metrics.Default()
	rec.Record(metrics.Call{Endpoint: metrics.EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	dir := t.TempDir()
	reportMetrics(&phlare.Options{Metrics: true, MonthlyQuota: 10000, Output: dir, Version: "v0.0.0-test"})

	if _, err := os.Stat(filepath.Join(dir, "flare-api-metrics.json")); err != nil {
		t.Fatalf("expected metrics JSON in output dir: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/... -run TestFatalfHelper -v`
Expected: FAIL — `undefined: reportMetrics`.

- [ ] **Step 3: Write minimal implementation**

In `cmd/search/search.go`, all three `phlare.NewFlareClient` calls gain
`phlare.WithMetricsRecorder(metrics.Default())` and
`phlare.WithGlobalSearchPageSize(opts.GlobalSearchPageSize)`. Then scope by entity:
- custom-query branch (`search.go:59`) → `fcq := fc.ForEntity(metrics.EntityCustomQuery)`, used for `QueryGlobalEvents` and `downloadZipFilesAndProcessPasswordResults`
- domain loop (`search.go:87-101`) → `fcd := fc.ForEntity(domain)`
- `FlareLeaksDatabaseSearchByDomain` loop (`search.go:486`) → `fc.ForEntity(domain).FlareSearchCredentialsByDomainASTP(domain)`
- `SearchEmailsInBulk` (`search.go:773`) → `fc.ForEntity(metrics.EntityBulkEmails).FlareBulkCredentialLookup(...)`

In `cmd/search/command.go`:

```go
// reportMetrics emits the Flare API usage report at most once per run.
func reportMetrics(opts *phlare.Options) {
	if err := metrics.Default().ReportOnce(metrics.ReportOptions{
		Enabled:      opts.Metrics,
		MonthlyQuota: opts.MonthlyQuota,
		OutputDir:    opts.Output,
		Version:      opts.Version,
		Colorize:     true,
	}); err != nil {
		utils.LogWarningf("could not write Flare API metrics report: %s\n", err.Error())
	}
}

// fatalf reports API usage before exiting. Quota is spent even when a run
// fails, and utils.LogFatalf calls os.Exit, which skips deferred work.
func fatalf(opts *phlare.Options, format string, args ...interface{}) {
	reportMetrics(opts)
	utils.LogFatalf(format, args...)
}
```

Replace the four dispatch-path `utils.LogFatalf` calls in `Run` (lines 79, 86, 92 and the scope/API-key checks that follow `LoadFromCommand`) with `fatalf(&opts.gophlareOptions, ...)`. Leave the pre-`LoadFromCommand` fatal at line 51 as-is — there are no options to report with yet.

In `cmd/root.go`, add the generic success-path hook:

```go
// PersistentPostRun emits the Flare API usage report after any subcommand.
// Registered on the root so a future Flare-touching subcommand gets it for
// free; it no-ops for commands that do not define --metrics.
RootCmd.PersistentPostRun = func(cmd *cobra.Command, _ []string) {
	enabled, err := cmd.Flags().GetBool("metrics")
	if err != nil || !enabled {
		return
	}
	quota, err := cmd.Flags().GetInt("monthly-quota")
	if err != nil {
		quota = metrics.DefaultMonthlyQuota
	}
	outputDir, _ := cmd.Flags().GetString("output")
	if err := metrics.Default().ReportOnce(metrics.ReportOptions{
		Enabled: true, MonthlyQuota: quota, OutputDir: outputDir,
		Version: cmd.Root().Version, Colorize: true,
	}); err != nil {
		utils.LogWarningf("could not write Flare API metrics report: %s\n", err.Error())
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./... -race -short && go build -v -trimpath -ldflags="-s -w" . && make lint`
Expected: PASS. Smoke test: `./gophlare search --help | grep -E 'metrics|monthly-quota|global-search-page-size'` shows all three flags with `5` as the page-size default.

- [ ] **Step 5: Commit**

```bash
git add cmd/
git commit -m "feat(cmd): emit Flare API usage report when --metrics is set"
```

---

### Task 9: Version bump and documentation

**Files:**
- Modify: `cmd/root.go:20` (`version`), `phlare/flareClient.go:15` (`gophlareClientVersion`) — **both to the same value**
- Modify: `README.md` (flag list, plus a "Flare API Usage Metrics" section)
- Modify: `docs/gophlare_search.md` (regenerated)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: everything above.
- Produces: no code API.

- [ ] **Step 1: Bump both version constants to `v1.5.0`**

A new user-facing flag with no breaking change is a minor bump. Both constants must match — `CLAUDE.md` calls this out explicitly.

- [ ] **Step 2: Regenerate CLI docs**

```bash
go build -v -trimpath -ldflags="-s -w" . && ./gophlare docs
```

- [ ] **Step 3: Update the README**

Add the three flags to the usage block and a section showing real report output, documenting that `--global-search-page-size` defaults to 5 and that larger pages cut quota burn at the cost of gateway-timeout risk. Note that ASTP searches do not draw on the Global Search quota, and that `/leaksdb/identities/by_accounts` billing is undocumented.

- [ ] **Step 4: Update the CHANGELOG**

```bash
git-cliff -o CHANGELOG.md   # falls back to a hand-written entry if git-cliff is unavailable
```

- [ ] **Step 5: Full pipeline and commit**

```bash
make fmt && make lint && go test ./... -race && go build -v -trimpath -ldflags="-s -w" .
git add -A
git commit -m "docs: document Flare API usage metrics and bump to v1.5.0"
```

---

## Self-Review

**Spec coverage:** D1 → Tasks 2, 4. D2 → Tasks 4, 6. D3 → Task 1. D4 → Tasks 2, 7. D5 → no ledger anywhere. D6 → Task 5 (`ForEntity`), Task 8 (call sites). D7 → Task 5 (`RefreshAPIToken` test). D8 → Task 5 (`WithBaseURL`). D9 → Tasks 5, 6, 7 (default-5 assertions). D10 → Task 8. Report format → Task 3. Flags table → Task 7. Files list → all tasks. Testing section → each task's steps 1 and 4. No gaps.

**Placeholder scan:** none — every code step carries real code or an exact edit target.

**Type consistency:** `metrics.Call`, `metrics.Endpoint`, `metrics.EndpointStat`, `metrics.EntityStat`, `metrics.Snapshot`, `metrics.ReportOptions`, `metrics.Recorder`, `phlare.ClientOption`, `phlare.DefaultGlobalSearchPageSize`, and `metrics.DefaultMonthlyQuota` are spelled identically in the tasks that define and consume them. `EndpointStat.Endpoint` is a `string` (not `Endpoint`) so the Task 6 comparison against `string(metrics.EndpointGlobalEventsSearch)` type-checks, and so the JSON artifact stays plainly readable.
