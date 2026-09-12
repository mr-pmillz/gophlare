# Flare API Query Metrics — Design

> Review correction: quota header differences cover an incomplete organization-wide
> interval, not total run spend. Single observations and quota increases yield
> unknown consumption. Page size reduces requests, with no guaranteed quota savings.
> The CLI now reports from resolved options with a recorder per invocation.
> See the README for current behavior; the design below records the original plan.


**Date:** 2026-09-10
**Status:** Approved
**Branch:** `feat/metrics`

## Problem

Flare bills Global Search against a monthly quota (10,000 units on a typical
license). gophlare can burn a large, invisible share of that quota in a single
run: `FlareEventsGlobalSearchByDomain` paginates with a cursor, so one domain
with a thousand stealer-log events issues hundreds of POSTs. Today an operator
has no way to see, during or after a run, how much quota an engagement cost or
which domain cost the most.

This design adds a `--metrics` flag that reports Flare API usage — total calls,
quota-consuming calls, and remaining monthly quota — broken out per endpoint and
per entity (domain / email batch / custom query).

## What the Flare docs actually say

Sourced from `api.docs.flare.io/concepts/rate-limits-and-quotas`, the v4
global-search and ASTP credentials-search endpoint references, and
`docs.flare.io/global-search-quota`.

**Quota:**
- Global Search draws on a monthly allocation. "1 search = 1 quota unit"; one
  search returns up to 100 events or credentials, and "requesting more than 100
  results (e.g. clicking 'fetch more') counts as an additional search."
- **Repeating the same search, or adjusting filters, within 10 minutes of the
  original query does not consume another search.** A local counter cannot model
  this.
- Two response headers report state:
  - `X-Flare-Global-Searches-Remaining` — searches left in the monthly allocation.
  - `X-Flare-Global-Searches-Batch-Reached` — returned when a search hits the
    maximum number of results.
- There is no API endpoint for querying quota status. The headers and the
  tenants page in the platform UI are the only sources.
- The docs do not state a universal default monthly quota; it is
  license-dependent.

**Rate limits (per organization):**
- Basic endpoints: 4 requests/second.
- Search endpoints: 1 request/second.
- Exceeding either returns `429` with `"code": "RATELIMIT_REACHED"`; the
  documented recovery is to wait 10 seconds. This matches the existing
  `time.Sleep(10 * time.Second)` retry in the pagination loops.

**Per-endpoint billing:**
- `/firework/v4/events/global/_search` is quota-bearing and on the Search tier.
- The ASTP credentials search "does not count towards your search quota but
  requires ASTP to be enabled on your account." (The *global* credentials search
  endpoint, which gophlare does not use, does count.)
- Billing for `/leaksdb/identities/by_accounts` is **undocumented**.

## Design decisions

### D1 — The response header is the source of truth

`phlare/http.go` currently returns only a status code; `resp.Header` is
discarded for every request. Because Flare's accounting includes a 10-minute
grace window and undocumented retry billing, a locally-derived count can only
ever be an upper bound. So:

- **Observed consumption** = first-seen `X-Flare-Global-Searches-Remaining`
  minus last-seen value. Authoritative.
- **Counted quota-bearing calls** = local counter. Reported alongside, as a
  bound, with the discrepancy explained in the report rather than hidden.

When both are present and differ, the report says why. When the header is never
returned, the report says so instead of printing a plausible-looking zero.

### D2 — Record in `FlareClient` methods, not in `DoReq`

Rejected: an observer callback on `phlare.Client`. `fc.Client` is a shared
pointer, so a per-entity label on `FlareClient` cannot reach a closure installed
on the shared `Client`; making it work requires copying `http.Client` per entity.

Rejected: an `http.RoundTripper`. A RoundTripper sees only the request, so
entity attribution would have to ride in `req.Context()` — but `DoReq` uses
`http.NewRequest`, with no context anywhere in the package.

Chosen: add `Client.DoReqWithHeaders` returning `(int, http.Header, error)`, with
`DoReq` delegating to it so existing behavior and every existing caller
(including `bloodhound/api.go`) are untouched. Each `FlareClient` method then
records explicitly — it already knows both its endpoint and its domain. Eight
call sites, all greppable, no hidden control flow.

### D3 — Endpoint classification lives in one table

A `metrics` package table maps each endpoint to a quota class and rate-limit
tier. Call sites reference constants, so "does this bill?" is declared once.

| Endpoint | Quota | Tier |
| --- | --- | --- |
| `POST /firework/v4/events/global/_search` | yes | search |
| `POST /astp/v2/credentials/_search` | no | search |
| `POST /astp/v2/cookies/_search` | no | search |
| `GET /firework/v2/activities/{uid}` | no | basic |
| `GET /firework/v2/activities/{uid}/download` | no | basic |
| `GET /firework/v2/activities/{uid}/download_file` | no | basic |
| `POST /leaksdb/identities/by_accounts` | **unknown** | basic |
| `POST /tokens/generate` | no | basic |

`unknown` renders as `?`. The report never asserts billing the docs do not state.

Endpoint identifiers are path *templates* — `{uid}`, not a concrete UID — so all
activity requests collapse onto one row instead of one row per stealer log.

### D4 — Always collect; the flag controls reporting

Counters are mutex-guarded integer increments against a per-run map, negligible
next to a network round trip. Collection is unconditional, so SDK consumers get
`metrics.Default().Snapshot()` without any flag. `--metrics` gates only the
report.

### D5 — Per-run only

No cross-run ledger. `X-Flare-Global-Searches-Remaining` already reports
authoritative month-to-date remaining, so a local monthly file would mostly
duplicate it while adding state to keep correct.

### D6 — Entity attribution via an immutable client copy

`FlareClient` gains `Entity string`. `ForEntity(name)` returns a shallow copy
with `Entity` set, sharing the `*Client` and `*Recorder` — no mutation of the
receiver, per the project's immutability rule. Methods that already take a
`domain` parameter use it directly; `FlareRetrieveEventActivitiesByID` and the
download methods, which have no domain parameter, read `fc.Entity`.

Entity names: the domain itself, `bulk-emails`, `custom-query`, `auth` (token
generation), and `-` for anything unattributed.

### D7 — Recorder must survive token refresh

`RefreshAPIToken` calls `NewFlareClient`, so without deliberate handling every
token refresh would silently reset all counters mid-run. `NewFlareClient` gains
variadic `...ClientOption` (`WithMetricsRecorder`, `WithBaseURL`,
`WithGlobalSearchPageSize`, `WithEntity`) — variadic keeps all three existing
call sites and every external SDK consumer compiling unchanged — and
`RefreshAPIToken` passes the current values through.

### D8 — `BaseURL` becomes overridable

`flareAPIBaseURL` is a hardcoded const, which is why `phlare/flareClient.go` —
701 lines containing all pagination, 429, and 5xx-retry logic — has no test file
at all. `FlareClient.BaseURL` defaults to the const and is settable via
`WithBaseURL`, enabling `httptest`-backed tests for both the new recording and
the existing retry behavior.

### D9 — Page size stays 5, becomes tunable

`--global-search-page-size` defaults to **5**, preserving current behavior. The
value was deliberately reduced from 10 previously and must not change by
default. The flag exists so an operator who knows their tenant tolerates larger
pages can halve their quota burn.

Carried on the client via `WithGlobalSearchPageSize` rather than added to
`FlareEventsGlobalSearchByDomain`'s already-long, README-documented signature.

### D10 — Report emission points

`Recorder.ReportOnce` is idempotent via `sync.Once`. Called from:
- `RootCmd.PersistentPostRun` — the success path, and generic, so any future
  Flare-touching subcommand gets it for free. Reads `--metrics` from the executed
  command's flags and no-ops when the flag is absent (e.g. `gophlare bloodhound`,
  which makes zero Flare API calls).
- A `fatalf` helper in `cmd/search/command.go` — quota is spent even when a run
  fails, and `gologger.Fatal()` calls `os.Exit`, which skips deferred work.

Known gap: a panic bypasses both.

## Report format

```
 FLARE API USAGE — gophlare v1.4.2 · 4m12s

 GLOBAL SEARCH QUOTA
   Monthly quota ................ 10,000  (--monthly-quota)
   Consumed this run (observed) .     87  via X-Flare-Global-Searches-Remaining
   Remaining .................... 8,213   17.9% of monthly quota used
   Quota-bearing calls counted ..     92  5 above observed — see note
   Batch limit reached ..........      2  searches truncated by Flare

 BY ENDPOINT
   ENDPOINT                                BILLS  CALLS  2xx  429  5xx  RETRIES    AVG
   /firework/v4/events/global/_search        yes     92   90    1    1        2   1.9s
   /astp/v2/credentials/_search               no     34   34    0    0        0   8.1s
   /leaksdb/identities/by_accounts             ?      3    3    0    0        0   4.0s
   TOTAL                                            237  233    1    3        2

 BY ENTITY
   ENTITY            ENDPOINT                              CALLS  QUOTA
   example.com       /firework/v4/events/global/_search       61     61
                     /firework/v2/activities/{uid}            35      —
   sub.example.com   /firework/v4/events/global/_search       31     31
   bulk-emails       /leaksdb/identities/by_accounts           3      ?
   TOTAL                                                     237     92

 note: counted (92) exceeds observed (87) — Flare does not bill repeat searches
       within 10 minutes, and 429/5xx retry billing is undocumented.
       Observed is authoritative.
```

Rendered with `text/tabwriter` (stdlib) and `fatih/color` (already a dependency).
No new dependencies. Entity rows are long-format rather than an
endpoint-per-column matrix so the table stays readable in a narrow terminal.
Endpoints and entities are sorted, making output deterministic and
golden-testable.

Also written to `<output>/flare-api-metrics.json` for scripting and engagement
artifacts.

## Flags

| Flag | Type | Default | Purpose |
| --- | --- | --- | --- |
| `--metrics` | bool | `false` | Emit the usage report at end of run |
| `--monthly-quota` | int | `10000` | Denominator for the percentage; labeled as operator-supplied |
| `--global-search-page-size` | int | `5` | `size` for global events search |

Registered in `phlare.ConfigureCommand` alongside the existing flags, resolved
through the standard `utils.ConfigureFlagOpts` chain (CLI → `GOFLARE_*` env →
viper config → default).

## Files

**Created**
- `metrics/endpoints.go` — endpoint constants, quota/tier catalog, entity constants
- `metrics/metrics.go` — `Recorder`, `Call`, `Snapshot`, header capture
- `metrics/report.go` — table rendering, JSON writer, `ReportOnce`
- `metrics/endpoints_test.go`, `metrics/metrics_test.go`, `metrics/report_test.go`
- `phlare/flareClient_test.go` — first tests for the client, via `WithBaseURL`
- `phlare/http_test.go` — header surfacing and `DoReq` behavior preservation

**Modified**
- `phlare/http.go` — add `DoReqWithHeaders`; `DoReq` delegates
- `phlare/types.go` — `FlareClient` gains `BaseURL`, `Metrics`, `Entity`, `GlobalSearchPageSize`
- `phlare/flareClient.go` — `ClientOption`s, `ForEntity`, `record`, 8 call sites, refresh passthrough, page size
- `phlare/options.go` — three new fields and flags
- `cmd/search/search.go` — wire recorder, `ForEntity` in the domain loops
- `cmd/search/command.go` — `fatalf` helper on the dispatch paths
- `cmd/root.go` — `PersistentPostRun`, version bump
- `phlare/flareClient.go` — `gophlareClientVersion` bump (must match `cmd/root.go`)
- `README.md`, `docs/gophlare_search.md`, `CHANGELOG.md`

## Testing

Table-driven, run under `-race`, targeting the project's 80% minimum.

- **metrics:** counter arithmetic; entity and endpoint attribution; quota
  classification including `unknown`; header parsing for valid, absent, and
  malformed values; observed-delta when the header appears mid-run, is present
  throughout, or never appears; `ReportOnce` idempotence; concurrent `Record`
  under `-race`; golden-string table output.
- **phlare/http.go:** `httptest` server returning quota headers — assert
  `DoReqWithHeaders` surfaces them, that headers are returned on non-2xx
  responses too, and that `DoReq` remains byte-identical including the non-2xx
  body drain and the string-target file write.
- **phlare/flareClient.go:** recording across cursor pagination; 429 retry; 5xx
  retry; recorder and page size surviving `RefreshAPIToken`.

## Risks and non-goals

- Local counts are an upper bound, never truth. The 10-minute grace window and
  retry billability are outside our knowledge. The report states this.
- `/leaksdb/identities/by_accounts` billing is undocumented and reported as `?`.
- `10000` is a flag default, not a documented universal quota. The report labels
  it as operator-supplied.
- Not building: cross-run/monthly ledgers, quota enforcement or pre-flight
  refusal, cost estimation before a run, or any change to default page size.
