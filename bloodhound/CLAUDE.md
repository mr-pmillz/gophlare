# CLAUDE.md - bloodhound/

Bloodhound-CE integration package. Provides API client, Neo4j interaction, and data types for correlating Flare breach data with Active Directory user data.

## Key Files

- **api.go** — `BHCEClient` wraps the Bloodhound-CE SDK (`bloodhound-go-sdk`). `NewBloodHoundAPIClient()` authenticates via `/api/v2/login` and creates an SDK client with bearer token. `SaveCustomQueryBloodHoundCE()` creates/replaces saved cypher queries.
- **neo4j.go** — `Neo4jDB` wraps a Neo4j session. `AddUserMetadata()` sets custom properties on User nodes (breach indicators). `GetAllUserData()` reads all User nodes and maps Neo4j properties to Go structs.
- **ingest.go** — Data parsing: `ParseFlareLeaksByDomainFile()`, `ParseHostLeaksJSONFile()` (JSONL format), `ParseStealerLogsHostLeaksFile()` (CSV), `ParseBloodHoundUsersFile()`. Credential pair extraction from Flare data with hash/password/encrypted value classification.
- **options.go** — `Options` struct and `ConfigureCommand()`/`LoadFromCommand()` for bloodhound subcommand flags.
- **types.go** — `BHCEUserData` with AD user properties, `FlareCredentialPairs` (has `UserID` field unlike the search package version), `HoardClientHostLeaksJSONL`, `StealerLogsCredentialCSVFile`.
- **postgres.go** — Commented-out Postgres code (kept for reference).

## Important Notes

- The `FlareCredentialPairs` struct here differs from `cmd/search`'s version — this one includes a `UserID` field for AD correlation.
- `FlareCreds` and `FlareCredentialPairs` are duplicated between this package and `cmd/search/` — they serve different correlation contexts.
- Neo4j custom properties added to User nodes: `hasbreachdata`, `hasbreachdataafterpwdlastset`, `breachedat`, `breachsources`, `pwdlastsetbeforebreach`.
