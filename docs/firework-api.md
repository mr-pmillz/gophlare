# Full Firework API

Requires Go **1.27.3** to build. The repository-root `firework-v2-openapi.json`,
`firework-v3-openapi.json`, and `firework-v4-openapi.json` define the supported
surface: **50 + 3 + 37 = 90 operations**, with every component schema retained.
This is parity with those snapshots, not a claim to cover undocumented endpoints
or APIs absent from them. Existing ASTP/search/BloodHound workflows remain intact.

## Authentication

Use the existing configuration file:

```yaml
API_KEYS:
  FLARE_API: your-api-key
  FLARE_TENANT_ID: 123
```

Or supply `GOFLARE_API_KEY` (`FLARE_API_KEY` is also recognized). Explicit
`--api-key` takes precedence over the environment, which takes precedence over
the config. Prefer the environment/config over command-line secrets.
`--auth-tenant-id` overrides the configured authentication tenant; zero selects
the user's default tenant. This is deliberately distinct from endpoint
parameters such as `--tenant-id` on `tenants get`.

`--api-token` or `GOFLARE_API_TOKEN` accepts an existing bearer token and skips
initial token generation. API keys are sent verbatim only to `/tokens/generate`;
endpoint calls use bearer tokens. Generated tokens are reused for 45 minutes.
`--base-url` and `--timeout` support alternate servers and request deadlines.
TLS verification remains enabled; authenticated cross-origin redirects are
rejected rather than forwarding credentials.

## Discover every operation

```bash
gophlare api list
gophlare api list --format json
gophlare api describe v4 list_identifiers_identifiers__get
gophlare api v4 list_identifiers_identifiers__get --help
gophlare api v3 get_identifiers_endpoint --size 20 --format json
```

Operation IDs are exactly those in the source specs, namespaced by version
(v2 and v3 reuse some IDs). Hyphenated operation-ID aliases are also accepted.
Each operation has flags for every declared path/query parameter. Parameter
underscores become hyphens; `types[]` becomes `--types`. Array flags repeat:

```bash
gophlare identifiers list --types domain --types keyword --is-disabled false
gophlare credentials identifier --identifier-id 123 --size 20
gophlare events get --uid 'stealer_log/example/123' --format json
```

Required parameters and JSON syntax are checked before authentication or network
calls. Numbers, booleans, arrays, and UUID path parameters are serialized by the
generated request builders. Schema constraints and business validation remain
the API server's responsibility; unknown JSON body fields are not discarded.

## Resource shortcuts

| Resource | Actions |
| --- | --- |
| `identifiers` | list, create, get, update, delete, toggle |
| `identifier-groups` | list, create, get, delete |
| `alerts`, `group-alerts` | list, create, update, delete |
| `events` | get, search, list, identifier, group, actions, metadata, expand, explain, assistance |
| `credentials` | search, actions, list, identifier |
| `profile` | get, update, tenants |
| `members` | list, create, get, update, enable, disable, permissions, tenants |
| `tenants` | list, create, get, update, archive, members, add-member, remove-member |
| `reports` | list, create, get, update, delete, archive, download |
| `entities` | list, get, relations |
| `matching-policies` | list, create, get, update, delete, identifier |
| `policy-assignments` | list, assign, unassign |
| `recommendations` | list, actions |
| `intel` | create, get, report, create-report-request, report-request |
| `sandbox` | upload-url |
| `audit-logs` | search |

`alerts` uses `--asset-id`, and `group-alerts` uses `--assets-group-id`, matching
the v2 spec's terminology for identifiers and identifier groups. The v4
shortcuts are preferred where both versions offer the same capability.
Legacy/deprecated variants remain callable through `api VERSION OPERATION_ID`.

## Table and JSON output

```bash
gophlare identifier-groups list
gophlare alerts list --asset-id 123 --columns id,name,type,frequency
gophlare identifiers list --format json
gophlare events list --body '{}' --columns metadata.uid,metadata.severity --wide
```

Tables use Unicode borders, stable column ordering, nested-column selection,
Unicode-aware alignment, and 48-column cell truncation. `--wide` disables
truncation; `--columns` selects exact fields. Terminal control characters are
removed from table cells. Empty collections display `No results.`

JSON output preserves the complete response envelope, unknown fields, nulls,
and large integers. It never adds table summaries or pagination messages to
stdout. Tables report a remaining cursor on stderr. APIs returning no body
produce `null` in JSON mode. Non-JSON/binary bodies require `--output-file`.

## Request bodies and writes

```bash
gophlare identifier-groups create --body '{"name":"Production"}'
gophlare identifiers update --identifier-id 123 --body @identifier-update.json
gophlare group-alerts create --assets-group-id 456 --body @alert.json
gophlare events actions --body - < actions.json
```

`--body` accepts inline JSON, `@filename`, or `-` for stdin. Use the schema named
in the command's help and the [Flare documentation index](https://api.docs.flare.io/llms.txt)
to construct full request bodies. The supplied bytes are sent without dropping
explicit false/zero/null values or fields absent from the snapshot.
Write and delete commands perform the named action immediately: there is no
interactive confirmation. HTTP errors return a nonzero exit status and retain
the status, response headers (including `Retry-After`), and error body in the SDK.
Requests are not automatically retried, avoiding accidental mutation replay or
unexpected extra search quota usage.

## Pagination and quota

One page is fetched by default. `--all` combines `items` across cursor pages and
retains the final response envelope. Empty pages with a nonempty `next` cursor
do **not** stop traversal. All other query/body filters remain unchanged.

```bash
gophlare identifiers list --all --max-pages 100 --format json
gophlare events search --body @search.json --all --max-pages 10 --format json
```

The default `--page-delay 1s` applies between pages. `--max-pages` defaults to
1000; when reached, output retains the last `next` cursor for manual resumption.
Pass it as `--from` for query pagination or as the body's `from` field for POST
searches. Cursors remain opaque strings and are never followed as URLs.
Repeated cursors fail rather than loop forever. `--all` is rejected for
operations without declared cursor pagination.

Global searches may consume quota, including when paginating. Rate limits and
429s are surfaced to the caller; no automatic sleep/retry hides quota exhaustion.
The existing `search --metrics` report remains scoped to the legacy search
workflows; the new API commands do not emit that report.

## Downloads

```bash
gophlare reports download --report-id 123 --output-file report.pdf
gophlare reports download --report-id 123 --output-file - > report.pdf
```

Responses stream to files with mode `0600`, without overwriting an existing
file. Error responses are not saved as successful downloads. An interrupted
download may leave a partial file and returns an error. `--output-file` saves
raw bytes rather than formatted output; combined with `--all`, it saves the
aggregated JSON. Cross-origin redirects are intentionally rejected; fetch a
returned presigned URL separately without Flare credentials when appropriate.

## Typed Go SDK

```go
client, err := flareapi.NewClient(flareapi.Config{
    APIKey: os.Getenv("GOFLARE_API_KEY"),
    TenantID: 123,
})
if err != nil {
    return err
}
response, err := client.V2.GetAssetsGroupsWithResponse(ctx)
if err != nil {
    return err
}
if response.StatusCode() != http.StatusOK {
    return fmt.Errorf("Flare HTTP %d: %s", response.StatusCode(), response.Body)
}
groups := response.JSON200
```

Import `github.com/mr-pmillz/gophlare/flareapi`. `client.V2`, `client.V3`, and
`client.V4` expose every generated operation, JSON body alias, parameter type,
response wrapper, and union helper from their respective packages. These typed
clients retain oapi-codegen's status-handling convention: inspect status and
the corresponding `JSON200`, `JSON201`, `JSON422`, etc. field. The raw
`client.Call(ctx, operation, request)` interface instead returns `*flareapi.APIError`
for non-2xx statuses, preserving untyped response data. `client.Collect` supports
bounded cursor traversal. Caller contexts cover authentication and API requests.

Optional Firework fields now use pointers, and nullable JSON fields use
`nullable.Nullable[T]`, distinguishing omission, explicit null, and zero values.
Use `.Set(value)`, `.SetNull()`, `.SetUnspecified()`, and `.Get()` on nullable
fields. For example, `PublicIdentifierUpdateRequestBody.GroupID.SetNull()` clears
a group association, while `.IsDisabled.Set(false)` explicitly enables an identifier.
Existing aliases in `phlare` reflect that change; migrate SDK struct literals and
accessors. Generated `WithBody` methods and `Request.Body` also accept raw JSON.
The upstream specs contain empty/untyped schemas and some imperfect response
definitions; generated types reflect those schemas rather than claiming stronger
contracts. Use the raw response body for any undocumented fields.

## Regeneration and coverage

```bash
make generate
go test ./flareapi/... ./cmd/api ./internal/output
```

`oapi-codegen` is pinned in `go.mod`. Generation is offline once dependencies
are cached. `make openapi-specs` explicitly refreshes the three root snapshots;
normal generation never downloads or edits specs. `internal/apigen` links each
operation to its generated request builder, so the CLI does not duplicate URL
construction or query serialization. Parity tests compare the registry with all
three specs and exercise every operation against mock servers. CI checks
regeneration for drift. No live Flare tenant or paid quota is needed for tests.
