package metrics

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QuotaUnitsUnknown is reported for endpoints whose quota billing Flare does
// not document. It is deliberately negative so it can never be mistaken for a
// real unit count in arithmetic or in the report.
const QuotaUnitsUnknown = -1

// Call describes one completed Flare API request.
type Call struct {
	// Endpoint is the path template the request hit.
	Endpoint Endpoint
	// Entity is the target the request was made on behalf of — a domain, or one
	// of the Entity* constants. Empty is normalized to EntityUnattributed.
	Entity string
	// Status is the HTTP status code. Transport failures record 0.
	Status int
	// Duration is the wall-clock time the request took.
	Duration time.Duration
	// Header is the response header, read for Flare's quota headers. Nil is
	// fine — a transport failure has no response.
	Header http.Header
	// Retry marks this attempt as a retry of a previous one, so the report can
	// distinguish 100 pages from 50 pages retried once each.
	Retry bool
}

// callKey groups counters by endpoint and entity.
type callKey struct {
	endpoint Endpoint
	entity   string
}

// counters accumulates the raw tallies for one endpoint/entity pair.
type counters struct {
	calls       int
	ok          int
	rateLimited int
	serverError int
	retries     int
	total       time.Duration
}

// Recorder accumulates Flare API usage for the lifetime of a run. It is safe
// for concurrent use: the paginated searches emit progress from a separate
// goroutine while requests are in flight.
//
// A nil *Recorder absorbs Record calls, so SDK consumers who never opt in to
// metrics pay nothing and need no nil checks.
type Recorder struct {
	mu      sync.Mutex
	started time.Time
	byKey   map[callKey]*counters

	// reported guards ReportOnce so the success path and the fatal path can
	// both call it without printing the report twice.
	reported sync.Once

	// Quota state observed from response headers. Tracking first and last
	// separately is what makes the delta authoritative: Flare's own accounting
	// includes a 10-minute free-repeat window we cannot model locally.
	quotaHeaderSeen bool
	firstRemaining  *int
	lastRemaining   *int
	batchReached    int
}

// NewRecorder returns a Recorder that starts timing the run immediately.
func NewRecorder() *Recorder {
	return &Recorder{
		started: time.Now(),
		byKey:   make(map[callKey]*counters),
	}
}

// defaultRecorder is the process-wide recorder the CLI uses, so instrumentation
// does not have to be threaded through every layer of the command tree.
var defaultRecorder = NewRecorder()

// Default returns the process-wide recorder.
func Default() *Recorder { return defaultRecorder }

// Record attributes one completed request. Safe on a nil receiver.
func (r *Recorder) Record(c Call) {
	if r == nil {
		return
	}

	entity := c.Entity
	if entity == "" {
		entity = EntityUnattributed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.noteQuotaHeaders(c.Header)

	key := callKey{endpoint: c.Endpoint, entity: entity}
	cnt, ok := r.byKey[key]
	if !ok {
		cnt = &counters{}
		r.byKey[key] = cnt
	}

	cnt.calls++
	cnt.total += c.Duration
	if c.Retry {
		cnt.retries++
	}
	switch {
	case c.Status >= 200 && c.Status < 300:
		cnt.ok++
	case c.Status == http.StatusTooManyRequests:
		cnt.rateLimited++
	case c.Status >= 500:
		cnt.serverError++
	}
}

// noteQuotaHeaders extracts Flare's quota headers. A missing or unparseable
// value is ignored rather than treated as zero: reporting "0 remaining" because
// a header was absent would be worse than reporting nothing at all.
//
// Callers must hold r.mu.
func (r *Recorder) noteQuotaHeaders(h http.Header) {
	if h == nil {
		return
	}
	if raw := strings.TrimSpace(h.Get(HeaderGlobalSearchesRemaining)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
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

// EndpointStat is the per-endpoint usage row in the report. Endpoint and the
// classification fields are strings so the JSON artifact reads plainly.
type EndpointStat struct {
	Endpoint    string        `json:"endpoint"`
	Quota       string        `json:"quota"`
	Tier        string        `json:"rate_limit_tier,omitempty"`
	Calls       int           `json:"calls"`
	OK          int           `json:"ok"`
	RateLimited int           `json:"rate_limited"`
	ServerError int           `json:"server_error"`
	Retries     int           `json:"retries"`
	QuotaUnits  int           `json:"quota_units"`
	AvgDuration time.Duration `json:"avg_duration_ns"`
}

// EntityStat is the per-entity usage row, with a breakdown by endpoint.
type EntityStat struct {
	Entity string `json:"entity"`
	Calls  int    `json:"calls"`
	// QuotaUnits counts only endpoints with documented billing.
	QuotaUnits int `json:"quota_units"`
	// QuotaUnknown is true when this entity used an endpoint whose billing is
	// undocumented, so QuotaUnits understates the real cost.
	QuotaUnknown bool           `json:"quota_unknown"`
	ByEndpoint   []EndpointStat `json:"by_endpoint"`
}

// Snapshot is an immutable view of a run's Flare API usage.
type Snapshot struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Duration    time.Duration `json:"duration_ns"`
	Version     string        `json:"gophlare_version,omitempty"`

	// MonthlyQuota is operator-supplied via --monthly-quota. Flare documents the
	// quota as license-dependent, so this is not authoritative.
	MonthlyQuota int `json:"monthly_quota"`

	// QuotaHeaderSeen reports whether Flare ever returned a quota header. When
	// false, every field below derived from it is nil and the report says so
	// rather than printing a misleading zero.
	QuotaHeaderSeen bool `json:"quota_header_seen"`
	RemainingFirst  *int `json:"remaining_first,omitempty"`
	RemainingLast   *int `json:"remaining_last,omitempty"`
	// ObservedConsumed is the authoritative quota spend for this run:
	// RemainingFirst - RemainingLast.
	ObservedConsumed *int `json:"observed_consumed,omitempty"`
	// CountedQuotaCalls is the local tally of quota-bearing requests. It is an
	// upper bound on spend, since Flare does not bill repeat searches within 10
	// minutes and retry billing is undocumented.
	CountedQuotaCalls int `json:"counted_quota_calls"`
	// BatchReached counts searches Flare truncated at its result maximum.
	BatchReached int `json:"batch_reached"`

	ByEndpoint []EndpointStat `json:"by_endpoint"`
	ByEntity   []EntityStat   `json:"by_entity"`
	Totals     EndpointStat   `json:"totals"`
}

// Snapshot aggregates everything recorded so far. monthlyQuota of 0 falls back
// to DefaultMonthlyQuota. Safe on a nil receiver, which yields an empty report.
func (r *Recorder) Snapshot(monthlyQuota int) Snapshot {
	if monthlyQuota <= 0 {
		monthlyQuota = DefaultMonthlyQuota
	}
	s := Snapshot{
		GeneratedAt:  time.Now(),
		MonthlyQuota: monthlyQuota,
		ByEndpoint:   make([]EndpointStat, 0),
		ByEntity:     make([]EntityStat, 0),
		Totals:       EndpointStat{Endpoint: "TOTAL"},
	}
	if r == nil {
		return s
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	s.Duration = time.Since(r.started)
	s.QuotaHeaderSeen = r.quotaHeaderSeen
	s.RemainingFirst = copyInt(r.firstRemaining)
	s.RemainingLast = copyInt(r.lastRemaining)
	s.BatchReached = r.batchReached
	if r.firstRemaining != nil && r.lastRemaining != nil {
		consumed := *r.firstRemaining - *r.lastRemaining
		s.ObservedConsumed = &consumed
	}

	byEndpoint := make(map[Endpoint]*counters)
	byEntity := make(map[string]map[Endpoint]*counters)
	for key, cnt := range r.byKey {
		accumulate(byEndpoint, key.endpoint, cnt)
		if _, ok := byEntity[key.entity]; !ok {
			byEntity[key.entity] = make(map[Endpoint]*counters)
		}
		accumulate(byEntity[key.entity], key.endpoint, cnt)
	}

	for _, endpoint := range sortedEndpoints(byEndpoint) {
		stat := newEndpointStat(endpoint, byEndpoint[endpoint])
		s.ByEndpoint = append(s.ByEndpoint, stat)
		addToTotals(&s.Totals, stat)
		if Lookup(endpoint).Quota == QuotaYes {
			s.CountedQuotaCalls += stat.Calls
		}
	}

	for _, entity := range sortedKeys(byEntity) {
		s.ByEntity = append(s.ByEntity, newEntityStat(entity, byEntity[entity]))
	}

	return s
}

// accumulate merges one counter set into a per-endpoint aggregate.
func accumulate(dst map[Endpoint]*counters, endpoint Endpoint, src *counters) {
	agg, ok := dst[endpoint]
	if !ok {
		agg = &counters{}
		dst[endpoint] = agg
	}
	agg.calls += src.calls
	agg.ok += src.ok
	agg.rateLimited += src.rateLimited
	agg.serverError += src.serverError
	agg.retries += src.retries
	agg.total += src.total
}

// newEndpointStat renders one aggregate as a report row.
func newEndpointStat(endpoint Endpoint, cnt *counters) EndpointStat {
	info := Lookup(endpoint)
	stat := EndpointStat{
		Endpoint:    string(endpoint),
		Quota:       info.Quota.String(),
		Tier:        string(info.Tier),
		Calls:       cnt.calls,
		OK:          cnt.ok,
		RateLimited: cnt.rateLimited,
		ServerError: cnt.serverError,
		Retries:     cnt.retries,
	}
	switch info.Quota {
	case QuotaYes:
		stat.QuotaUnits = cnt.calls
	case QuotaUnknown:
		stat.QuotaUnits = QuotaUnitsUnknown
	case QuotaNo:
		stat.QuotaUnits = 0
	}
	if cnt.calls > 0 {
		stat.AvgDuration = cnt.total / time.Duration(cnt.calls)
	}
	return stat
}

// newEntityStat rolls an entity's endpoints into a single row plus a breakdown.
func newEntityStat(entity string, byEndpoint map[Endpoint]*counters) EntityStat {
	stat := EntityStat{Entity: entity, ByEndpoint: make([]EndpointStat, 0, len(byEndpoint))}
	for _, endpoint := range sortedEndpoints(byEndpoint) {
		row := newEndpointStat(endpoint, byEndpoint[endpoint])
		stat.ByEndpoint = append(stat.ByEndpoint, row)
		stat.Calls += row.Calls
		if row.QuotaUnits == QuotaUnitsUnknown {
			stat.QuotaUnknown = true
			continue
		}
		stat.QuotaUnits += row.QuotaUnits
	}
	return stat
}

// addToTotals folds a row into the TOTAL row. QuotaUnits from undocumented
// endpoints are excluded rather than subtracted; EntityStat.QuotaUnknown and
// the per-endpoint "?" carry that caveat instead.
func addToTotals(totals *EndpointStat, stat EndpointStat) {
	totals.Calls += stat.Calls
	totals.OK += stat.OK
	totals.RateLimited += stat.RateLimited
	totals.ServerError += stat.ServerError
	totals.Retries += stat.Retries
	if stat.QuotaUnits > 0 {
		totals.QuotaUnits += stat.QuotaUnits
	}
}

// sortedEndpoints returns a map's endpoints in a stable order so report output
// and its golden tests are deterministic.
func sortedEndpoints(m map[Endpoint]*counters) []Endpoint {
	out := make([]Endpoint, 0, len(m))
	for e := range m {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

// sortedKeys returns a map's entity names in a stable order.
func sortedKeys(m map[string]map[Endpoint]*counters) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// copyInt defensively copies an optional int out of the recorder's state.
func copyInt(v *int) *int {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
