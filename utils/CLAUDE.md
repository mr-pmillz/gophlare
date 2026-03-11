# CLAUDE.md - utils/

Shared utility functions used across all packages.

## Key Files

- **flags.go** — `ConfigureFlagOpts()` is the central flag/config resolution function. Resolution priority: CLI flag → `GOFLARE_*` env var (via indirection) → viper config value → default. Handles: type coercion (string/int/bool/[]string), file path resolution, file-to-lines reading (`ReadFileLines`), comma-separated string splitting. `LoadFromCommandOpts` controls behavior per-flag. **Gotcha:** When `IsFilePath` + `CommaInStringToSlice` are both true, the config path has an early IsFilePath check before the "slice-like config" block — without it, file paths get treated as comma-separated values instead of being read.
- **string.go** — String utilities:
  - `IsHash()` — Identifies MD5/SHA-1/SHA-256/SHA-512/Blowfish/pbkdf2 hashes by regex. Used to separate cleartext passwords from hashes in Flare's `Hash` field.
  - `IsLikelyAnEncryptedValue()` — Detects base64-encoded encrypted values.
  - `IsUserIDFormatMatch()` — Dynamically generates regex from sample format (e.g., `a12345` → `^[A-Za-z]\d{5}$`).
  - `IsUserID()` — Matches common AD user ID patterns (letter+digits, DOMAIN\username).
  - `ExtractBaseDomain()` — Extracts base domain from URL or DNS name, handles multi-part TLDs (.co.uk).
  - `SanitizeString()` — Replaces non-alphanumeric chars with underscores, limits to 255 chars.
  - `FormatDate()` — Accepts MM-DD-YYYY, YYYY-MM-DD, MM/DD/YYYY, YYYY/MM/DD → RFC3339.
- **file.go** — File I/O: path resolution (~/ expansion), existence checks, JSON/CSV/JSONL marshalling, `UnzipToTemp()` with zip-slip protection, `CSVsToExcel()` (via excelize), gzip compression.
- **slice.go** — `SortUnique()`, `ContainsPrefix()`, natural sort implementation (`StringSlice`).
- **log.go** — Logging wrappers around `gologger` with colored emoji output and file-based error logging (`gophlare-error-log-{date}.json`).
- **constants.go** — `AlphaTLDs` list used by `ExtractBaseDomain()`.

## Testing

Tests exist for: `string.go`, `file.go`, `slice.go`, `flags.go`. Run with:
```bash
go test -v ./utils/...
```
