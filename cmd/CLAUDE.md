# CLAUDE.md - cmd/

CLI layer using cobra + viper. Each subcommand lives in its own subdirectory.

## Structure

- **root.go** — Root cobra command. Config via viper: `--config` flag or `~/.config/gophlare/config.yaml`. Env var prefix: `GOFLARE_`. `bindFlags()` syncs viper config values to cobra flags.
- **search/** — `gophlare search` subcommand. The main workflow:
  1. `LoadFromCommand()` parses all flags into `phlare.Options`
  2. `phlare.NewScope()` normalizes inputs
  3. Dispatches to stealer log download, credential search, or bulk email search
- **bloodhound/** — `gophlare bloodhound` subcommand. Correlates Flare breach data with Bloodhound-CE AD data. Can update Neo4j with breach indicators and create custom cypher queries.
- **docs/** — Hidden `gophlare docs` command. Generates markdown documentation via `cobra/doc`.

## Adding a New Subcommand

1. Create `cmd/<name>/command.go` with a `Command` var
2. Define an `Options` struct wrapping the domain package's options
3. Implement `configureCommand()` to register flags and `LoadFromCommand()` to parse them
4. Add `RootCmd.AddCommand(<name>.Command)` in `cmd/root.go`

## cmd/search/ Details

- **command.go** — Flag registration, validation (output required, domains/query not both empty), scope creation, dispatch logic
- **search.go** — Core search workflows: `DownloadAllStealerLogPasswordFiles()`, `FlareLeaksDatabaseSearchByDomain()`, `SearchEmailsInBulk()`. Stealer log pipeline: query events → download zips → parse passwords/cookies → write CSV/XLSX → insert to SQLite DB
- **cookie.go** — Cookie parsing from stealer log files (tab-separated format), expiration checking, high-value cookie identification (Microsoft SSO, Azure, Google auth cookies), CookieBro JSON export format

## cmd/bloodhound/ Details

- **command.go** — Flag registration and validation for Neo4j + Bloodhound-CE connection params
- **bloodhound.go** — `ProcessData()` orchestrates: correlate leak data → write cred stuffing files → optionally update Neo4j and create Bloodhound cypher queries. `CorrelateLeakDataWithBloodHoundData()` uses parallel processing (4 workers) for datasets >1000 users.
