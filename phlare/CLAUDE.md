# CLAUDE.md - phlare/

Core SDK package for the Flare API. This is the central package that other packages depend on.

## Key Files

- **options.go** — `Options` struct with all CLI/config fields. `ConfigureCommand()` registers cobra flags. `LoadFromCommand()` parses flags via `utils.ConfigureFlagOpts()`. Many fields are `interface{}` (string or []string) — this is intentional for flexible input (file path, comma-separated, or single value).
- **scope.go** — `Scope` normalizes `Options` interface{} fields into typed `[]string` slices via `resolveToSlice()`. Out-of-scope domain filtering happens in `addDomains()`.
- **flareClient.go** — `FlareClient` manages JWT auth (Basic auth → bearer token), auto-refresh on expiry. All API calls live here: global events search, credentials search (ASTP), cookies search, stealer log downloads, bulk credential lookup.
- **types.go** — All Flare API request/response structs. `FlareTime` is a custom `time.Time` that handles the API's inconsistent timestamp formats.
- **time.go** — `FlareTime` JSON unmarshalling (tries ~8 formats), plus `Scan`/`Value` for GORM.
- **http.go** — Generic HTTP `Client` with `DoReq()`. When `target` is a `string`, response body is written to that file path. Otherwise JSON-decoded (or XML if Content-Type says so).
- **db.go** — SQLite via GORM (`glebarez/sqlite`). `InitializeBreachDatabase()` creates DB at `~/.config/gophlare/database/`. Batch inserts with upsert on UID conflict.
- **dbModels.go** — GORM models. `StealerLog` is the main model with 11 has-many relationships (credentials, cookies, files, resources, feature domains/emails/IPs/etc.).

## Patterns

- **API pagination**: All search methods use cursor-based pagination with `Next *string`. Pagination loops use labeled `break flarePaginate`.
- **Rate limiting**: 429 responses trigger a 10-second sleep and retry.
- **Token refresh**: `FlareClient` checks `IsAPITokenExpired()` before requests and calls `RefreshAPIToken()` if needed.
- **FlareTime**: Always use `FlareTime` instead of `time.Time` for API response fields. It implements `json.Unmarshaler`, `driver.Valuer`, and `sql.Scanner`.
- **Database writes**: Use `CreateInBatches()` for bulk inserts. `InsertStealerLogActivities()` upserts on UID.
