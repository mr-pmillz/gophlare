package metrics

import (
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

// remainingHeader builds a response header carrying a quota-remaining value.
func remainingHeader(v string) http.Header {
	return http.Header{HeaderGlobalSearchesRemaining: []string{v}}
}

// findEndpoint returns the stat row for an endpoint, failing if absent.
func findEndpoint(t *testing.T, s Snapshot, e Endpoint) EndpointStat {
	t.Helper()
	for _, stat := range s.ByEndpoint {
		if stat.Endpoint == string(e) {
			return stat
		}
	}
	t.Fatalf("no ByEndpoint row for %q in %+v", e, s.ByEndpoint)
	return EndpointStat{}
}

func TestRecorderObservedConsumedFromHeaderDelta(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("9000")})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("8998")})

	s := r.Snapshot(10000)

	if !s.QuotaHeaderSeen {
		t.Fatal("QuotaHeaderSeen = false, want true")
	}
	if s.ObservedConsumed == nil || *s.ObservedConsumed != 2 {
		t.Errorf("ObservedConsumed = %v, want 2", derefInt(s.ObservedConsumed))
	}
	if s.RemainingFirst == nil || *s.RemainingFirst != 9000 {
		t.Errorf("RemainingFirst = %v, want 9000", derefInt(s.RemainingFirst))
	}
	if s.RemainingLast == nil || *s.RemainingLast != 8998 {
		t.Errorf("RemainingLast = %v, want 8998", derefInt(s.RemainingLast))
	}
	if s.CountedQuotaCalls != 2 {
		t.Errorf("CountedQuotaCalls = %d, want 2", s.CountedQuotaCalls)
	}
}

func TestRecorderQuotaHeaderVariants(t *testing.T) {
	tests := []struct {
		name          string
		headers       []http.Header
		wantSeen      bool
		wantConsumed  *int
		wantRemaining *int
	}{
		{
			name:     "header never returned",
			headers:  []http.Header{nil, nil},
			wantSeen: false,
		},
		{
			name:     "malformed value is ignored",
			headers:  []http.Header{remainingHeader("banana")},
			wantSeen: false,
		},
		{
			name:     "empty value is ignored",
			headers:  []http.Header{remainingHeader("")},
			wantSeen: false,
		},
		{
			name:          "single observation yields no delta but a remaining value",
			headers:       []http.Header{remainingHeader("7500")},
			wantSeen:      true,
			wantConsumed:  new(0),
			wantRemaining: new(7500),
		},
		{
			name:          "header appearing mid-run still anchors the delta",
			headers:       []http.Header{nil, remainingHeader("500"), remainingHeader("497")},
			wantSeen:      true,
			wantConsumed:  new(3),
			wantRemaining: new(497),
		},
		{
			name:          "surrounding whitespace is tolerated",
			headers:       []http.Header{remainingHeader(" 100 "), remainingHeader("99")},
			wantSeen:      true,
			wantConsumed:  new(1),
			wantRemaining: new(99),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRecorder()
			for _, h := range tt.headers {
				r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: h})
			}

			s := r.Snapshot(10000)

			if s.QuotaHeaderSeen != tt.wantSeen {
				t.Errorf("QuotaHeaderSeen = %v, want %v", s.QuotaHeaderSeen, tt.wantSeen)
			}
			if derefInt(s.ObservedConsumed) != derefInt(tt.wantConsumed) {
				t.Errorf("ObservedConsumed = %v, want %v", derefInt(s.ObservedConsumed), derefInt(tt.wantConsumed))
			}
			if derefInt(s.RemainingLast) != derefInt(tt.wantRemaining) {
				t.Errorf("RemainingLast = %v, want %v", derefInt(s.RemainingLast), derefInt(tt.wantRemaining))
			}
		})
	}
}

func TestRecorderStatusClassification(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		wantOK          int
		wantRateLimited int
		wantServerError int
	}{
		{"200 is a success", 200, 1, 0, 0},
		{"204 is a success", 204, 1, 0, 0},
		{"429 is rate limited", 429, 0, 1, 0},
		{"500 is a server error", 500, 0, 0, 1},
		{"503 is a server error", 503, 0, 0, 1},
		{"504 is a server error", 504, 0, 0, 1},
		{"401 is counted but is neither success nor server error", 401, 0, 0, 0},
		{"404 is counted but is neither success nor server error", 404, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRecorder()
			r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: tt.status})

			stat := findEndpoint(t, r.Snapshot(10000), EndpointGlobalEventsSearch)

			if stat.Calls != 1 {
				t.Errorf("Calls = %d, want 1 (every attempt is counted)", stat.Calls)
			}
			if stat.OK != tt.wantOK {
				t.Errorf("OK = %d, want %d", stat.OK, tt.wantOK)
			}
			if stat.RateLimited != tt.wantRateLimited {
				t.Errorf("RateLimited = %d, want %d", stat.RateLimited, tt.wantRateLimited)
			}
			if stat.ServerError != tt.wantServerError {
				t.Errorf("ServerError = %d, want %d", stat.ServerError, tt.wantServerError)
			}
		})
	}
}

func TestRecorderQuotaUnitsPerEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		want     int
	}{
		{"quota-bearing endpoint counts every call", EndpointGlobalEventsSearch, 2},
		{"non-billing endpoint counts zero", EndpointASTPCredentialsSearch, 0},
		{"undocumented endpoint reports -1", EndpointBulkAccounts, QuotaUnitsUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRecorder()
			r.Record(Call{Endpoint: tt.endpoint, Entity: "example.com", Status: 200})
			r.Record(Call{Endpoint: tt.endpoint, Entity: "example.com", Status: 200})

			if got := findEndpoint(t, r.Snapshot(10000), tt.endpoint).QuotaUnits; got != tt.want {
				t.Errorf("QuotaUnits = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRecorderRetriesAndBatchReached(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 429})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Retry: true,
		Header: http.Header{HeaderGlobalSearchesBatchReached: []string{"true"}}})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200,
		Header: http.Header{HeaderGlobalSearchesBatchReached: []string{"true"}}})

	s := r.Snapshot(10000)

	if got := findEndpoint(t, s, EndpointGlobalEventsSearch).Retries; got != 1 {
		t.Errorf("Retries = %d, want 1", got)
	}
	if s.BatchReached != 2 {
		t.Errorf("BatchReached = %d, want 2", s.BatchReached)
	}
}

func TestRecorderEntityAttribution(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "zeta.com", Status: 200})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "alpha.com", Status: 200})
	r.Record(Call{Endpoint: EndpointActivityByID, Entity: "alpha.com", Status: 200})
	r.Record(Call{Endpoint: EndpointTokenGenerate, Entity: "", Status: 200})

	s := r.Snapshot(10000)

	gotEntities := make([]string, 0, len(s.ByEntity))
	for _, e := range s.ByEntity {
		gotEntities = append(gotEntities, e.Entity)
	}
	wantEntities := []string{EntityUnattributed, "alpha.com", "zeta.com"}
	if !slices.Equal(gotEntities, wantEntities) {
		t.Errorf("ByEntity names = %v, want %v (sorted, empty entity normalized)", gotEntities, wantEntities)
	}

	for _, e := range s.ByEntity {
		if e.Entity != "alpha.com" {
			continue
		}
		if e.Calls != 2 {
			t.Errorf("alpha.com Calls = %d, want 2", e.Calls)
		}
		if e.QuotaUnits != 1 {
			t.Errorf("alpha.com QuotaUnits = %d, want 1 (only the global search bills)", e.QuotaUnits)
		}
		if len(e.ByEndpoint) != 2 {
			t.Errorf("alpha.com ByEndpoint has %d rows, want 2", len(e.ByEndpoint))
		}
		if !slices.IsSortedFunc(e.ByEndpoint, func(a, b EndpointStat) int {
			switch {
			case a.Endpoint < b.Endpoint:
				return -1
			case a.Endpoint > b.Endpoint:
				return 1
			default:
				return 0
			}
		}) {
			t.Errorf("alpha.com ByEndpoint is not sorted: %+v", e.ByEndpoint)
		}
	}
}

func TestRecorderEntityFlagsUnknownQuota(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointBulkAccounts, Entity: EntityBulkEmails, Status: 200})

	s := r.Snapshot(10000)

	if len(s.ByEntity) != 1 {
		t.Fatalf("ByEntity has %d rows, want 1", len(s.ByEntity))
	}
	if !s.ByEntity[0].QuotaUnknown {
		t.Error("QuotaUnknown = false, want true when an entity used an undocumented endpoint")
	}
}

func TestRecorderTotalsAndAverageDuration(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Duration: 2 * time.Second})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Duration: 4 * time.Second})
	r.Record(Call{Endpoint: EndpointASTPCookiesSearch, Entity: "example.com", Status: 429, Duration: time.Second})

	s := r.Snapshot(10000)

	if s.Totals.Calls != 3 {
		t.Errorf("Totals.Calls = %d, want 3", s.Totals.Calls)
	}
	if s.Totals.OK != 2 {
		t.Errorf("Totals.OK = %d, want 2", s.Totals.OK)
	}
	if s.Totals.RateLimited != 1 {
		t.Errorf("Totals.RateLimited = %d, want 1", s.Totals.RateLimited)
	}
	if s.Totals.QuotaUnits != 2 {
		t.Errorf("Totals.QuotaUnits = %d, want 2", s.Totals.QuotaUnits)
	}
	if got := findEndpoint(t, s, EndpointGlobalEventsSearch).AvgDuration; got != 3*time.Second {
		t.Errorf("AvgDuration = %v, want 3s", got)
	}
}

func TestRecorderSnapshotDefaultsQuotaWhenUnset(t *testing.T) {
	r := NewRecorder()

	if got := r.Snapshot(0).MonthlyQuota; got != DefaultMonthlyQuota {
		t.Errorf("Snapshot(0).MonthlyQuota = %d, want %d", got, DefaultMonthlyQuota)
	}
}

// TestNilRecorderIsANoOp keeps the SDK path free for consumers who never opt in
// to metrics: a nil *Recorder must absorb calls rather than panic.
func TestNilRecorderIsANoOp(t *testing.T) {
	var r *Recorder

	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	s := r.Snapshot(10000)
	if s.Totals.Calls != 0 {
		t.Errorf("nil recorder Snapshot Totals.Calls = %d, want 0", s.Totals.Calls)
	}
}

func TestDefaultRecorderIsShared(t *testing.T) {
	if Default() == nil {
		t.Fatal("Default() = nil, want a recorder")
	}
	if Default() != Default() {
		t.Error("Default() returned different recorders; the CLI relies on a single process-wide recorder")
	}
}

func TestRecorderIsConcurrencySafe(t *testing.T) {
	r := NewRecorder()
	const goroutines, perGoroutine = 50, 100

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for range perGoroutine {
				r.Record(Call{
					Endpoint: EndpointGlobalEventsSearch,
					Entity:   "example.com",
					Status:   200,
					Duration: time.Millisecond,
					Header:   remainingHeader("9000"),
				})
			}
		}(g)
	}
	wg.Wait()

	if got := r.Snapshot(10000).Totals.Calls; got != goroutines*perGoroutine {
		t.Errorf("Totals.Calls = %d, want %d", got, goroutines*perGoroutine)
	}
}

// derefInt renders a *int for comparison and error messages, mapping nil to a
// sentinel that cannot collide with a real quota count.
//
//go:fix inline
func derefInt(v *int) int {
	if v == nil {
		return -999
	}
	return *v
}
