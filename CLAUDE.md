# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gophlare is a Go SDK and CLI wrapper for the [flare.io](https://flare.io) API, used for threat intelligence — searching breach credentials, stealer logs, and cookies. It also integrates with Bloodhound-CE for Active Directory breach data correlation. The tool is designed for authorized security testing and penetration testing engagements.

## Build & Development Commands

```bash
# Build
go build -v -trimpath -ldflags="-s -w" .

# Run tests (local, uses tparse for formatting)
make test

# Run a single test
go test -v -run TestFunctionName ./package/...

# Lint
make lint
# or directly:
golangci-lint run -c .golangci-lint.yml -v ./... --timeout 10m

# Format check
make fmt

# Full pipeline
make all   # fmt + lint + build + test + release
```

## Pre-commit Hooks

Pre-commit hooks run TruffleHog (secret scanning), golangci-lint, and tests on commit/push. These run via `make lint` and `make test`.

## Architecture

### CLI Layer (cobra + viper)

- `main.go` — Entry point, initializes `~/.config/gophlare/` and runs the root command.
- `cmd/root.go` — Root cobra command. Config loaded via viper from `--config` flag or `~/.config/gophlare/config.yaml`. Env vars prefixed with `GOFLARE_`.
- `cmd/search/command.go` — `gophlare search` subcommand. Delegates to `phlare.Options` for flag loading, creates a `Scope`, then dispatches to stealer log, credential, or email search functions.
- `cmd/bloodhound/command.go` — `gophlare bloodhound` subcommand for correlating breach data with Bloodhound-CE.
- `cmd/docs/command.go` — Generates CLI documentation.

### Core SDK (`phlare/`)

- `phlare/options.go` — `Options` struct and `ConfigureCommand()` to register all cobra flags. `LoadFromCommand()` parses flags using `utils.ConfigureFlagOpts()`. Several fields (`Domains`, `Emails`, `Severity`, etc.) are `interface{}` because they can be a string, `[]string`, or file path.
- `phlare/scope.go` — `Scope` struct normalizes `Options` interface{} fields into typed `[]string` slices, with out-of-scope domain filtering.
- `phlare/flareClient.go` — `FlareClient` handles API auth (JWT token via Basic auth), auto-refresh on expiry, and all Flare API calls (global events search, credentials search, cookies search, stealer log downloads). Pagination uses a `Next` cursor field.
- `phlare/types.go` — All Flare API request/response structs. `FlareTime` is a custom `time.Time` wrapper that handles multiple timestamp formats from the API.
- `phlare/time.go` — `FlareTime` JSON unmarshalling (tries multiple formats), `Scan`/`Value` for GORM database serialization.
- `phlare/http.go` — Generic HTTP `Client` with `DoReq()` method. Response decoding dispatches to JSON or XML based on Content-Type. When `target` is a string, it writes the body to that file path.
- `phlare/db.go` — SQLite database (via GORM + `glebarez/sqlite`) for persisting breach data. Stored at `~/.config/gophlare/database/`. Batch inserts for stealer log activities and credentials with upsert on UID conflict.
- `phlare/dbModels.go` — GORM model definitions for all database tables.

### Bloodhound Integration (`bloodhound/`)

- `bloodhound/api.go` — Bloodhound-CE API client (user enumeration).
- `bloodhound/neo4j.go` — Neo4j queries for correlating breach data with AD data.
- `bloodhound/postgres.go` — Alternative Postgres-based Bloodhound queries.
- `bloodhound/ingest.go` — Data ingestion and correlation logic.

### Utilities (`utils/`)

- `utils/flags.go` — `ConfigureFlagOpts()` is the central flag resolution function. Priority: CLI flag > env var (via GOFLARE_ prefix) > viper config value > default. Handles type coercion, file-to-slice reading, and comma-separated string splitting.
- `utils/string.go` — String utilities including `IsUserIDFormatMatch()` which dynamically generates regex patterns from sample user ID formats (e.g., `a12345` becomes `^[A-Za-z]\d{5}$`).
- `utils/file.go` — File helpers (path resolution, existence checks, gzip compression, JSON/CSV/XLSX writing).
- `utils/log.go` — Logging wrappers around `gologger` with colored output and file-based error logging.
- `utils/slice.go` — Slice utilities (dedup, contains, filtering).

### Config (`config/`)

- `config/config.go` — `GoPhlareConfig` struct with `API_KEYS.FLARE_API` and `API_KEYS.FLARE_TENANT_ID` loaded via viper.
- `config/config.yaml` — Example config file (contains real API keys — do not commit changes to this file).

## Key Patterns

- **Flag resolution chain**: CLI flag → `GOFLARE_*` env var → viper config (YAML) → default value. All handled in `utils.ConfigureFlagOpts()`.
- **Interface{} for multi-type inputs**: `Options` fields like `Domains`, `Emails`, `Severity` use `interface{}` to accept string, `[]string`, or file paths. `Scope` normalizes these via `resolveToSlice()`.
- **FlareTime**: Custom time type that handles multiple Flare API timestamp formats. Used throughout API response structs and GORM models. When adding new time fields, use `FlareTime` not `time.Time`.
- **API pagination**: Flare API uses cursor-based pagination via `Next *string` field. Pagination loops use labeled `break flarePaginate` pattern.
- **Version**: Hardcoded in both `cmd/root.go` (`version` var) and `phlare/flareClient.go` (`gophlareClientVersion` const). Both must be updated together for releases.

## Related Projects

- **Sister project**: `goreconasoutsider` at `~/projects/goreconasoutsider` shares the same `utils/flags.go` ConfigureFlagOpts pattern. Features may be ported between them (e.g., `ReadFileLines` was ported from goreconasoutsider to gophlare).

## Linting

Uses golangci-lint v2 config (`.golangci-lint.yml`). Key enabled linters: bodyclose, dupl, errorlint, gocognit, goconst, gocritic, gosec, govet, staticcheck, unused. The `gocognit` nolint directive is used on complex `LoadFromCommand` methods.
