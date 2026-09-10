// Package metrics accounts for gophlare's Flare API usage: how many requests a
// run made, which of them drew down the monthly Global Search quota, and how
// much of that quota remains.
//
// Flare's own accounting is not fully reproducible client-side — repeating a
// search within 10 minutes is free, and whether a retried 429 or 5xx bills is
// undocumented — so this package treats the X-Flare-Global-Searches-Remaining
// response header as the source of truth and reports local counters alongside
// it as an upper bound.
package metrics

import "slices"

// Flare response headers that carry quota state. There is no API endpoint for
// querying quota, so these headers and the platform's tenants page are the only
// sources.
const (
	// HeaderGlobalSearchesRemaining reports the number of searches left in the
	// monthly Global Search allocation.
	HeaderGlobalSearchesRemaining = "X-Flare-Global-Searches-Remaining"
	// HeaderGlobalSearchesBatchReached is returned when a search hits the
	// maximum number of results, meaning the results were truncated.
	HeaderGlobalSearchesBatchReached = "X-Flare-Global-Searches-Batch-Reached"
)

// DefaultMonthlyQuota is the assumed monthly Global Search allocation. Flare
// documents the quota as license-dependent and never states a universal
// default, so this is only a sensible starting point for the --monthly-quota
// flag and is always labelled as operator-supplied in the report.
const DefaultMonthlyQuota = 10000

// Entity names used when a request cannot be attributed to a target domain.
const (
	EntityAuth         = "auth"
	EntityBulkEmails   = "bulk-emails"
	EntityCustomQuery  = "custom-query"
	EntityUnattributed = "-"
)

// Endpoint identifies a Flare API endpoint for usage accounting. Values are
// path templates rather than concrete URLs: keeping the {uid} placeholder
// collapses every stealer-log activity request onto a single report row instead
// of producing one row per log.
type Endpoint string

// The Flare API endpoints gophlare calls.
const (
	EndpointTokenGenerate        Endpoint = "/tokens/generate"
	EndpointGlobalEventsSearch   Endpoint = "/firework/v4/events/global/_search"
	EndpointActivityByID         Endpoint = "/firework/v2/activities/{uid}"
	EndpointActivityDownload     Endpoint = "/firework/v2/activities/{uid}/download"
	EndpointActivityDownloadFile Endpoint = "/firework/v2/activities/{uid}/download_file"
	// EndpointASTPCredentialsSearch is an API path, not a secret; gosec's G101
	// heuristic fires on the word "credentials".
	EndpointASTPCredentialsSearch Endpoint = "/astp/v2/credentials/_search" //nolint:gosec
	EndpointASTPCookiesSearch     Endpoint = "/astp/v2/cookies/_search"
	EndpointBulkAccounts          Endpoint = "/leaksdb/identities/by_accounts"
)

// QuotaClass describes whether an endpoint draws down the monthly Global Search
// quota.
type QuotaClass int

const (
	// QuotaNo means the endpoint is documented as not counting against the
	// Global Search quota.
	QuotaNo QuotaClass = iota
	// QuotaYes means each request counts against the Global Search quota.
	QuotaYes
	// QuotaUnknown means Flare does not document this endpoint's billing. It is
	// reported as "?" so gophlare never asserts a cost it cannot substantiate.
	QuotaUnknown
)

// String renders the quota class for the usage report.
func (q QuotaClass) String() string {
	switch q {
	case QuotaYes:
		return "yes"
	case QuotaNo:
		return "no"
	default:
		return "?"
	}
}

// RateLimitTier is the per-organization rate limit Flare applies to an
// endpoint. Exceeding a tier returns 429 with code RATELIMIT_REACHED.
type RateLimitTier string

const (
	// TierBasic allows 4 requests per second.
	TierBasic RateLimitTier = "basic"
	// TierSearch allows 1 request per second.
	TierSearch RateLimitTier = "search"
)

// EndpointInfo is the accounting metadata for a single endpoint.
type EndpointInfo struct {
	Endpoint Endpoint
	Quota    QuotaClass
	Tier     RateLimitTier
}

// endpointCatalog is the single source of truth for endpoint billing. Call
// sites reference the Endpoint constants so "does this bill?" is declared once
// here rather than duplicated across the client.
//
// Sources: api.docs.flare.io/concepts/rate-limits-and-quotas and the v4
// global-search and ASTP credentials-search endpoint references. The ASTP
// credentials search is explicitly documented as not counting toward the search
// quota; billing for /leaksdb/identities/by_accounts is not documented at all.
var endpointCatalog = map[Endpoint]EndpointInfo{
	EndpointTokenGenerate:         {EndpointTokenGenerate, QuotaNo, TierBasic},
	EndpointGlobalEventsSearch:    {EndpointGlobalEventsSearch, QuotaYes, TierSearch},
	EndpointActivityByID:          {EndpointActivityByID, QuotaNo, TierBasic},
	EndpointActivityDownload:      {EndpointActivityDownload, QuotaNo, TierBasic},
	EndpointActivityDownloadFile:  {EndpointActivityDownloadFile, QuotaNo, TierBasic},
	EndpointASTPCredentialsSearch: {EndpointASTPCredentialsSearch, QuotaNo, TierSearch},
	EndpointASTPCookiesSearch:     {EndpointASTPCookiesSearch, QuotaNo, TierSearch},
	EndpointBulkAccounts:          {EndpointBulkAccounts, QuotaUnknown, TierBasic},
}

// Lookup returns the accounting metadata for an endpoint. An endpoint missing
// from the catalog is reported as unknown-billing rather than free, so a newly
// added API call cannot silently understate quota consumption.
func Lookup(e Endpoint) EndpointInfo {
	if info, ok := endpointCatalog[e]; ok {
		return info
	}
	return EndpointInfo{Endpoint: e, Quota: QuotaUnknown, Tier: TierBasic}
}

// KnownEndpoints returns every catalogued endpoint in sorted order.
func KnownEndpoints() []Endpoint {
	endpoints := make([]Endpoint, 0, len(endpointCatalog))
	for e := range endpointCatalog {
		endpoints = append(endpoints, e)
	}
	slices.Sort(endpoints)
	return endpoints
}
