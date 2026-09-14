# Changelog

All notable changes to this project will be documented [here](https://github.com/mr-pmillz/gophlare/blob/main/CHANGELOG.md?ref_type=heads)

## [1.4.3](https://github.com/mr-pmillz/gophlare/compare/v1.4.2...v1.4.3) - 2026-09-14

### ✨: New features

- Feat: derive gophlare version from Git and Go build metadata

Remove the duplicated release version strings from cmd/root.go and
phlare/flareClient.go so releases no longer require source-code version
bumps. Follow sj's build-time version injection pattern and share one
resolver across the CLI, metrics reports, and default HTTP user-agent.

Add internal/version with linker-injected versions taking precedence over
runtime/debug.ReadBuildInfo. Use the embedded module version for ordinary
Go builds and go install module@version, falling back to dev when metadata
is unavailable. When gophlare is imported as an SDK, resolve its dependency
version and module replacements instead of reporting the host program's
version. Preserve caller-supplied user-agent strings.

Wire version metadata into every existing build path:
- Make derives VERSION from git describe --tags --always --dirty and uses
  it for local builds, cross-compiled binaries, and archive filenames.
- Cross-compilation builds the package instead of main.go so Go can retain
  module and version-control metadata.
- GoReleaser injects v-prefixed release and snapshot versions.
- Docker includes Git for automatic metadata and accepts a VERSION build
  argument for source archives without Git history.

Replace release-policy checks against hardcoded Go strings with stable
tag validation. Keep branch-name, stable-version, and ancestry protections
while allowing release branches and tags to supply the binary version.
Update installation, contributor, and repository guidance to explain the
automatic version sources, development fallbacks, and explicit overrides.

Add coverage for release and development metadata, missing metadata,
linker overrides, SDK dependency replacements, custom user-agents, and
valid/invalid stable release tags.

Validation:
- make fmt and make build passed.
- make test passed with race detection; internal/version reached 100%
  statement coverage. Local HTTP tests required loopback socket access.
- make lint passed with zero issues.
- Python release-policy tests and goreleaser check passed.
- GoReleaser snapshot build and --version verification passed.
- CLI smoke checks verified Git-derived Make versions, native Go module
  metadata, the dev fallback, and explicit release-version injection.
- git diff --check passed.

The Dockerfile was reviewed; a container image was not built locally. - ([7649cf8](https://github.com/mr-pmillz/gophlare/commit/7649cf876297fe3dea098a7d545a776adab7ef42))

### ⚙️  Miscellaneous

- Merge pull request #16 from mr-pmillz/feat/auto-version

feat: derive gophlare version from Git and Go build metadata - ([aad1855](https://github.com/mr-pmillz/gophlare/commit/aad18556d7eabce338cb89765dc0a2e7097a445e))
- Merge pull request #15 from mr-pmillz/main

sync main back to develop - ([493479f](https://github.com/mr-pmillz/gophlare/commit/493479f5b57e806e4250abdaac190b47b93b5bba))

## [1.4.2](https://github.com/mr-pmillz/gophlare/compare/v1.4.1...v1.4.2) - 2026-09-14

### ✨ New features

- Feat(phlare): add DoReqWithHeaders to expose response headers

Flare reports quota state only in response headers
(X-Flare-Global-Searches-Remaining), which DoReq discarded entirely. The
request body moves to DoReqWithHeaders and DoReq delegates to it, so its
signature and behavior are unchanged for bloodhound/api.go and external SDK
consumers.

Headers are returned on non-2xx responses too, so a 429's quota headers
survive the existing error-body drain path.

Adds the first tests for this file: header surfacing on 2xx and on
429/504/401, DoReq/DoReqWithHeaders equivalence, the string-target file
write used by stealer-log downloads, and a nil header on transport failure.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([861d2d0](https://github.com/mr-pmillz/gophlare/commit/861d2d0d08ae647a167f4d8e1434d0251f1d1fc3))
- Feat(metrics): add concurrency-safe API usage recorder

Records every Flare request by endpoint and entity, tracking successes,
429s, 5xx, and retries. Captures X-Flare-Global-Searches-Remaining and
derives observed quota spend from the first/last delta, which is
authoritative: Flare does not bill repeat searches within 10 minutes and
retry billing is undocumented, so the local counter is only an upper bound.

A missing or unparseable header is ignored rather than read as zero, and a
nil *Recorder absorbs calls so SDK consumers pay nothing when they do not
opt in.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([c56aa29](https://github.com/mr-pmillz/gophlare/commit/c56aa2948225183a3a70f62bb5ce4944ae4401ee))
- Feat(metrics): add Flare endpoint quota classification catalog

Declares which Flare endpoints draw down the monthly Global Search quota in
one place. /firework/v4/events/global/_search bills; the ASTP searches are
documented as not counting; /leaksdb/identities/by_accounts is undocumented
and classified QuotaUnknown so the report renders "?" rather than asserting
a cost that cannot be substantiated.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([f132827](https://github.com/mr-pmillz/gophlare/commit/f132827aad72fbc8585e2c10dfaa58cd210d91d4))
- Docs: add design spec and implementation plan for Flare API metrics

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([d61763e](https://github.com/mr-pmillz/gophlare/commit/d61763e1cb4b48897de545dc61f783387504a9c9))

### ✨: New features

- Feat(cmd): emit Flare API usage report when --metrics is set

Adds three flags on the search command via the standard
utils.ConfigureFlagOpts chain: --metrics (report only; collection is always
on so SDK consumers get a Snapshot for free), --monthly-quota (default
10000, labeled operator-supplied since Flare sets it per license), and
--global-search-page-size (default 5, unchanged).

All three NewFlareClient call sites get the process-wide recorder, and each
workflow scopes its client with ForEntity so the report attributes usage per
domain, plus synthetic entities for custom queries and bulk email lookups.

The report fires from two places. RootCmd.PersistentPostRun covers the
success path and is generic, so a future Flare-touching subcommand gets it
free while `gophlare bloodhound` — which makes no Flare calls — no-ops. A
fatalf helper covers the dispatch-path failures, because quota is spent even
when a run fails and utils.LogFatalf calls os.Exit, which would skip a
defer. ReportOnce is sync.Once-guarded so both firing is harmless.

Verified end to end: with empty credentials the fatal path still prints the
report and writes flare-api-metrics.json before exiting, and correctly
states that no calls were made and no quota header was seen rather than
printing a zero.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([b592928](https://github.com/mr-pmillz/gophlare/commit/b592928ada8619d492cdaf6bf7e53a5c71896b2f))
- Feat(phlare): record usage metrics for every Flare API call

Adds ClientOptions (WithMetricsRecorder, WithBaseURL,
WithGlobalSearchPageSize, WithEntity) as a variadic tail on NewFlareClient,
so all existing call sites and external SDK consumers compile unchanged.
ForEntity returns a shallow copy sharing the HTTP client and recorder, which
attributes requests per domain without mutating the receiver.

RefreshAPIToken now carries the recorder, base URL, page size, and entity
across. Without that, every token refresh would hand back a client with a
fresh recorder and silently reset all counters mid-run.

All eight API call sites move to DoReqWithHeaders and record their endpoint,
entity, status, and duration. The three pagination loops track a retry flag
so the attempt after a 429 or 5xx is counted as a retry rather than as
another page.

Two supporting changes:
- The hardcoded flareAPIBaseURL is replaced by FlareClient.BaseURL at all
  eight URL builders. This is what makes the file testable, and it fixes a
  bug introduced mid-change where only the token URL honored the override,
  leaving the search calls pointed at the live API.
- The global search `size` comes from GlobalSearchPageSize, defaulting to 5
  (unchanged) with a zero-guard for clients built without the constructor.

First tests for this 800-line file: options and defaults, ForEntity
immutability, recorder survival across refresh, page size on the wire,
per-page recording with quota-header delta, 429 retry accounting, ASTP
recorded as non-billing, and entity inheritance for domain-less methods.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([bf071bb](https://github.com/mr-pmillz/gophlare/commit/bf071bb490a836ad3073b2a4a8cc35a262d9e891))
- Feat(metrics): render usage report table and JSON artifact

Three blocks: quota summary with dot leaders, per-endpoint counts, and a
long-format per-entity breakdown that stays readable in a narrow terminal.
Sorted output keeps it golden-testable.

The report refuses to invent numbers. With no quota header it says so
instead of printing a zero Remaining or a computed percentage, an
undocumented endpoint renders "?" rather than a cost, and when the local
count exceeds the header-derived figure it explains the 10-minute
free-repeat window and names observed as authoritative.

ReportOnce is sync.Once-guarded so the success path and the fatal path can
both call it. 93.6% coverage.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([991d20c](https://github.com/mr-pmillz/gophlare/commit/991d20c1c98e9fe87ed8269cdda43376e0e26a18))

### 🐛 Bug fixes

- Fix: harden quota metrics and automate secure releases

Correct quota reporting to distinguish organization-wide header observations
from this run's usage, handle quota resets and incomplete baselines, and
preserve JSON output and reporting errors when terminal output fails.
Use a fresh recorder per CLI invocation, honor metrics configuration, and
validate quota and page-size settings. Bound transient retries per page and
cover reporting, pagination, and client behavior with regression tests.

Upgrade Go to 1.26.6 and update x/crypto, x/net, kin-openapi, Excelize,
oapi-codegen, and klauspost/compress to address the supplied Dependabot
alerts and additional scan findings. Document the advisory mapping and the
unimported, deprecated OpenPGP package with no available fixed version.

Adapt the nomore403 develop/release/hotfix flow with reusable CI, race and
coverage checks, vulnerability scanning, branch policy, changelog commits,
and tagging of exact PR merge commits. Gate publication on CI and validate
release versions and ancestry; publish multiarch GHCR manifests and archive
provenance. Use repository-scoped App tokens with GOPHLARE_APP_CLIENT_ID
and GOPHLARE_APP_PRIVATE_KEY for release notes, changelogs, and tags.

Add contributor guidance, CODEOWNERS, issue/PR templates, and Dependabot
configuration. Keep module files unchanged during builds and pin CI tools.

Validation: full Go race suite, golangci-lint, build and module checks,
package-level govulncheck, CLI metrics and Excel export smoke checks,
release policy tests, and GoReleaser configuration checks passed.
Actionlint passed with the documented code-quality permission exclusion.
Live release publication and App authentication were not exercised locally. - ([d80a33c](https://github.com/mr-pmillz/gophlare/commit/d80a33cbeb857e6ab3bb8cf8ce5b9b1292f6c74a))

### 🚜 Refactor

- Refactor(phlare): modernize interface{} to any

Applied by the go fix modernizer. `any` is a pure alias for `interface{}`,
so this is a symmetric rename with no semantic change (166 insertions, 166
deletions) — the Options fields stay deliberately untyped for flexible
string/[]string/file-path input, and all 232 omitempty tags in types.go are
preserved.

Separated from the metrics feature so that diff stays readable.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([19bc8b4](https://github.com/mr-pmillz/gophlare/commit/19bc8b4ea0e3a560659213cc2c06fc0c485b7f58))

### 📚 Documentation

- Docs: document Flare API usage metrics and bump to v1.5.0

Bumps both version constants together (cmd/root.go and
phlare/flareClient.go), regenerates the CLI docs, and adds a README section
covering which endpoints bill, why the header-derived figure is
authoritative over the local counter, and the page-size/quota tradeoff.

Notes explicitly that --global-search-page-size defaults to 5 and that
raising it to 10 roughly halves quota burn at the cost of gateway-timeout
risk, so the choice stays the operator's.

CHANGELOG written by hand in git-cliff's format; git-cliff is not installed
on this machine.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com> - ([0bcdeab](https://github.com/mr-pmillz/gophlare/commit/0bcdeab7769651bd0c88b006319a673637a3f1d3))

### 🛠 Improvements

- Update .gitignore - ([09e86fe](https://github.com/mr-pmillz/gophlare/commit/09e86fe19e5f1de7cb75e58468b2c6a706ccef40))
- Update CHANGELOG.md - ([acfb983](https://github.com/mr-pmillz/gophlare/commit/acfb9832a66b6385c1de779f70f59a572a13c2b8))

### ⚙️  Miscellaneous

- Merge pull request #14 from mr-pmillz/release/v1.4.2

Release/v1.4.2 - ([2484a7e](https://github.com/mr-pmillz/gophlare/commit/2484a7e394cf42e1708425d55f42d5401ba3fe8e))
- Chore: update changelog - ([e33d1d9](https://github.com/mr-pmillz/gophlare/commit/e33d1d9340faac24b6be4f674026f24088449cb5))
- Set gophlare version - ([8c6ed12](https://github.com/mr-pmillz/gophlare/commit/8c6ed129e2cebe0aa305684874fbb4307ff4bd87))
- Merge pull request #12 from mr-pmillz/dependabot/github_actions/develop/github-actions-dc7855c1e5

ci(deps): bump the github-actions group with 4 updates - ([fec3129](https://github.com/mr-pmillz/gophlare/commit/fec3129236bec48f6c50971ca89e8f06d2c68372))
- Merge branch 'develop' into dependabot/github_actions/develop/github-actions-dc7855c1e5 - ([59bd2f9](https://github.com/mr-pmillz/gophlare/commit/59bd2f9a0fd5eea46c23f8975d8b71ad615e2d6c))
- Ci(deps): bump the github-actions group with 4 updates

Bumps the github-actions group with 4 updates: [orhun/git-cliff-action](https://github.com/orhun/git-cliff-action), [actions/upload-code-coverage](https://github.com/actions/upload-code-coverage), [docker/setup-buildx-action](https://github.com/docker/setup-buildx-action) and [actions/attest](https://github.com/actions/attest).


Updates `orhun/git-cliff-action` from 4.8.0 to 4.9.0
- [Release notes](https://github.com/orhun/git-cliff-action/releases)
- [Commits](https://github.com/orhun/git-cliff-action/compare/f50e11560dce63f7c33227798f90b924471a88b5...3d96a18cc4ec17e9dc69ddcc424ccafaf1f78ce2)

Updates `actions/upload-code-coverage` from 1.4.1 to 1.4.2
- [Commits](https://github.com/actions/upload-code-coverage/compare/1c15be36fc3733ba839b1dd643bd9556e4426dc1...d8e329117199404bba6fc81efe8093dc7c015e34)

Updates `docker/setup-buildx-action` from 4.2.0 to 4.3.0
- [Release notes](https://github.com/docker/setup-buildx-action/releases)
- [Commits](https://github.com/docker/setup-buildx-action/compare/bb05f3f5519dd87d3ba754cc423b652a5edd6d2c...37fe631027851001ddb9b187196cc803df7f5f0e)

Updates `actions/attest` from 4.2.1 to 4.2.2
- [Release notes](https://github.com/actions/attest/releases)
- [Changelog](https://github.com/actions/attest/blob/main/RELEASE.md)
- [Commits](https://github.com/actions/attest/compare/508db95dd578ae2727ebd6217d5ba78e4fbda05d...1e69f48acb82d1966a394da916b4c1698aa569d6)

---
updated-dependencies:
- dependency-name: orhun/git-cliff-action
  dependency-version: 4.9.0
  dependency-type: direct:production
  update-type: version-update:semver-minor
  dependency-group: github-actions
- dependency-name: actions/upload-code-coverage
  dependency-version: 1.4.2
  dependency-type: direct:production
  update-type: version-update:semver-patch
  dependency-group: github-actions
- dependency-name: docker/setup-buildx-action
  dependency-version: 4.3.0
  dependency-type: direct:production
  update-type: version-update:semver-minor
  dependency-group: github-actions
- dependency-name: actions/attest
  dependency-version: 4.2.2
  dependency-type: direct:production
  update-type: version-update:semver-patch
  dependency-group: github-actions
...

Signed-off-by: dependabot[bot] <support@github.com> - ([c418c3b](https://github.com/mr-pmillz/gophlare/commit/c418c3b40f429c2caee15cd502ce60ca09908958))
- Merge pull request #11 from mr-pmillz/dependabot/go_modules/develop/go-modules-87bc5cd2bc

chore(deps): bump the go-modules group with 3 updates - ([5295907](https://github.com/mr-pmillz/gophlare/commit/529590782d3b8d69e708f3cc8a84921f012df6fa))
- Merge pull request #13 from mr-pmillz/dependabot/github_actions/develop/docker/setup-qemu-action-4.3.0

ci(deps): bump docker/setup-qemu-action from 3.7.0 to 4.3.0 - ([bbaf95a](https://github.com/mr-pmillz/gophlare/commit/bbaf95a9c57c89ba1791097630bb119f9d211d9a))
- Ci(deps): bump docker/setup-qemu-action from 3.7.0 to 4.3.0

Bumps [docker/setup-qemu-action](https://github.com/docker/setup-qemu-action) from 3.7.0 to 4.3.0.
- [Release notes](https://github.com/docker/setup-qemu-action/releases)
- [Commits](https://github.com/docker/setup-qemu-action/compare/c7c53464625b32c7a7e944ae62b3e17d2b600130...1f40c72289eff860ee54a304f1438e3cff362e0a)

---
updated-dependencies:
- dependency-name: docker/setup-qemu-action
  dependency-version: 4.3.0
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com> - ([84548fb](https://github.com/mr-pmillz/gophlare/commit/84548fb86e75abbad7dbd5604159e302e5a84a61))
- Merge pull request #9 from mr-pmillz/develop

Develop - ([6aa53e9](https://github.com/mr-pmillz/gophlare/commit/6aa53e987f770455b2b01c18acb533c84773de63))
- Merge pull request #8 from mr-pmillz/feat/metrics

Metrics Tracking for API Quota Usage - ([359fe75](https://github.com/mr-pmillz/gophlare/commit/359fe75a996919d35a912e8978ceaa08d7fa1981))

## [1.4.1](https://github.com/mr-pmillz/gophlare/compare/v1.4.0...v1.4.1) - 2026-05-26

### ⚙️  Miscellaneous

- Version bump - ([b68a00a](https://github.com/mr-pmillz/gophlare/commit/b68a00abaae03f16cc714c9d684666636132e153))
- Phlare: emit periodic progress logs during paginated searches

FlareEventsGlobalSearchByDomain, FlareSearchCookiesByDomain, and
FlareSearchCredentialsByDomainASTP can run for many minutes against
large tenants. Until now they produced no output during pagination,
leaving the user unable to tell whether the SDK was still working or
stuck.

Spin up a 30s ticker goroutine in each function that logs the running
count of accumulated items. Use sync/atomic.Int64 so the ticker can
safely read the count without racing the main loop's append.
defer close(progressDone) guarantees the goroutine exits on every
return path. - ([1f414bc](https://github.com/mr-pmillz/gophlare/commit/1f414bc879918676b21243369087c4b07b56cbe1))
- Version pin actions to hashes and bump go version and deps in go.mod - ([137d438](https://github.com/mr-pmillz/gophlare/commit/137d438b7b9b939c703bc60da52759ffc5f8c773))

## [1.4.0](https://github.com/mr-pmillz/gophlare/compare/v1.3.9...v1.4.0) - 2026-05-18

### 🛠 Improvements

- Update changelog - ([2043c2b](https://github.com/mr-pmillz/gophlare/commit/2043c2ba47516e7a09e2633d195743f1d18ce8c7))

### ⚙️  Miscellaneous

- Resolved linter issues and version bump - ([6bc1265](https://github.com/mr-pmillz/gophlare/commit/6bc126580aa1a65d16da0cfe33160660aa140b8b))
- Merge pull request #7 from cham423/fix/credentials-search-timeout-and-logerror-masking

Fix Flare gateway timeouts and three layers of error masking - ([978c67c](https://github.com/mr-pmillz/gophlare/commit/978c67c96554838115cd877ed86882d6477c5c8a))
- Phlare: don't JSON-decode error response bodies in DoReq

DoReq returned (statusCode, DecodeResponse(resp, target)) regardless
of HTTP status. When the API returned a non-2xx with a non-JSON body
(e.g. Flare's gateway returning the plain text "upstream request
timeout" on a 504), the JSON decoder errored on the first byte with
"invalid character 'u' looking for beginning of value" — and callers
that check `err` before `statusCode` saw only the decoder failure,
never the real HTTP status.

Skip the decode entirely on non-2xx responses. Drain the body so the
connection can be reused and return (statusCode, nil); the caller's
existing `if statusCode != 200` branch then handles it cleanly.

Combined with the new 502/503/504 retry path, this means transient
Flare gateway timeouts now surface as a clean retry+success rather
than a confusing JSON parse error. - ([abc84fe](https://github.com/mr-pmillz/gophlare/commit/abc84fe3374487a13eb1ef4dda9a1d6d031bd585))
- Utils: LogError no longer masks the caller's original error

LogError opens a dated log file (gophlare-error-log-<date>.json) in
the CWD on every call. When that open fails — most commonly because
the filesystem is read-only (CI runners, hardened containers,
os.Chroot'd processes) — it returned the filesystem error in place
of the caller's original `err`:

    f, openFileErr := os.OpenFile(fname, ...)
    if openFileErr != nil {
        return openFileErr   // <-- masks the caller's err
    }

Every API failure surfaced as "open gophlare-error-log-...: read-only
file system" instead of the real cause (504s, 429s, JSON decode
errors, etc.). The actual error became unreachable from outside
gophlare.

File write is now best-effort: on open failure we skip the file tee,
still log via gologger to stderr, and always return the caller's
original `err`. The public contract is unchanged — LogError still
returns an error, it's just now the real one. - ([4e4548d](https://github.com/mr-pmillz/gophlare/commit/4e4548df79e8ae76b75a947c0a8bafb04d304115))
- Phlare: make credentials search resilient to Flare gateway timeouts

Two related fixes for FlareSearchCredentialsByDomainASTP — the
hardcoded page size was overshooting Flare's gateway timeout, and the
endpoint had no retry path for the resulting 5xx responses.

1) Lower hardcoded `size` from "10000" to "100"

   Flare's gateway returns HTTP 504 "upstream request timeout" when
   the backend can't materialize a page within ~30 seconds. The
   `astp/v2/credentials/_search` latency scales roughly linearly with
   `size` (measured against a single tenant, slow-day conditions):

     size=10   ~3.9s   size=100  ~8.0s   size=300  ~24s
     size=50   ~6.3s   size=200  ~13.2s  size=500  504 at 30.2s

   Size=10000 was always going to 504 on any non-trivial corpus.
   Size=100 leaves >20s of headroom on slow days; pagination via the
   existing Next cursor loop handles arbitrary total result sizes, so
   per-domain ceiling is unchanged.

2) Retry on 502/503/504 (mirrors the existing 429 handling)

   Flare gateway timeouts are transient under load. Without retry,
   a single 504 fails the entire per-domain pull even if the next
   call would have succeeded. Added 502/503/504 → sleep+continue
   alongside the existing 429 case in all three pagination loops
   (credentials/leaksdb, cookies, credentials/astp). Bounded by the
   outer http.Client timeout (default 10 minutes). - ([5d581cb](https://github.com/mr-pmillz/gophlare/commit/5d581cb8c5f37db838fb1e31f6f1d433b00b5130))

## [1.3.9](https://github.com/mr-pmillz/gophlare/compare/v1.3.8...v1.3.9) - 2026-03-11

### ✨ New features

- Add ReadFileLines to ConfigureFlagOpts and simplify scope.go

Port ReadFileLines from goreconasoutsider to read file contents as []string
directly in ConfigureFlagOpts, eliminating redundant file-reading in scope.go.
Fix comma-separated values not being split when IsFilePath is true and the
value is not an existing file. Simplify scope.go from ~170 lines to ~35 lines
using a resolveToSlice() type-switch helper.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com> - ([18d6a9c](https://github.com/mr-pmillz/gophlare/commit/18d6a9ce168a82ec8b1db3d941ef4e85c2141d45))

### 🛠 Improvements

- Update changelog - ([6cc4810](https://github.com/mr-pmillz/gophlare/commit/6cc481073189ea981f1796306038e3aca7b75168))

### ⚙️  Miscellaneous

- Version bump - ([fd58483](https://github.com/mr-pmillz/gophlare/commit/fd5848363752e268a859d267e7bd6afa1c222c51))

## [1.3.8](https://github.com/mr-pmillz/gophlare/compare/v1.3.7...v1.3.8) - 2026-01-17

### 🐛 Bug fixes

- Fix more time.Time to FlareTime - ([c6c92ee](https://github.com/mr-pmillz/gophlare/commit/c6c92eef6d74406ff1b7be7702bd3bb131cfdf7a))

### 🛠 Improvements

- Update changelog - ([67ecc2a](https://github.com/mr-pmillz/gophlare/commit/67ecc2a870793cbb9e8b0a9965e529974dab4f14))

## [1.3.7](https://github.com/mr-pmillz/gophlare/compare/v1.3.6...v1.3.7) - 2026-01-15

### ✨ New features

- Add support for ISO 8601 date time format - ([264daa2](https://github.com/mr-pmillz/gophlare/commit/264daa2a41b23dad2b191a2b3b96d9588f83cbd3))

### 🛠 Improvements

- Update changelog - ([6e4fb96](https://github.com/mr-pmillz/gophlare/commit/6e4fb9648981a1c43d0a6be1f30f84f2739adb60))

## [1.3.6](https://github.com/mr-pmillz/gophlare/compare/v1.3.5...v1.3.6) - 2025-12-11

### ⚡ Performance

- Optimize cred stuffing files - ([b86f914](https://github.com/mr-pmillz/gophlare/commit/b86f914dace4affbbd8f0a58238febc66e09786d))

### 🛠 Improvements

- Update changelog - ([8b57521](https://github.com/mr-pmillz/gophlare/commit/8b57521388f091a8b7d914b0e3df094021fc14cc))

### ⚙️  Miscellaneous

- Version bump - ([90abb38](https://github.com/mr-pmillz/gophlare/commit/90abb3856e4a0b9a1170983112e1acb209bd1fa5))

## [1.3.5](https://github.com/mr-pmillz/gophlare/compare/v1.3.4...v1.3.5) - 2025-12-02

### 📦 Dependencies

- Bump deps - ([39aee3a](https://github.com/mr-pmillz/gophlare/commit/39aee3a3ca68ddb963926b998a06d61d087a7b1d))

### 🛠 Improvements

- Update changelog - ([9015b9d](https://github.com/mr-pmillz/gophlare/commit/9015b9dd97e0f1fa4a5153eee6f654801bccb30e))

### ⚙️  Miscellaneous

- Resolve code scanning alerts - ([a02f792](https://github.com/mr-pmillz/gophlare/commit/a02f79279f40f50bc818131634ed6414ad516ca7))

## [1.3.4](https://github.com/mr-pmillz/gophlare/compare/v1.3.3...v1.3.4) - 2025-11-26

### 🐛 Bug fixes

- Fix ConfigureFlagOpts - ([d58b98c](https://github.com/mr-pmillz/gophlare/commit/d58b98cf407ae1911320e55d8af97ef134967133))

### 🛠 Improvements

- Update changelog - ([5338d28](https://github.com/mr-pmillz/gophlare/commit/5338d28cc1c0dcfef1a8be66205d7605e877914a))

## [1.3.3](https://github.com/mr-pmillz/gophlare/compare/v1.3.2...v1.3.3) - 2025-11-25

### 🐛 Bug fixes

- Fixed options parser - ([d4bd76c](https://github.com/mr-pmillz/gophlare/commit/d4bd76c3c51c1063cae6f5b7288da20129ae8814))

### 🛠 Improvements

- Update changelog - ([0a6651b](https://github.com/mr-pmillz/gophlare/commit/0a6651b00275f879eecde31b0f8e508f3e2b86e9))

## [1.3.2](https://github.com/mr-pmillz/gophlare/compare/v1.3.1...v1.3.2) - 2025-11-25

### 🐛 Bug fixes

- Git-cliff buggin out - ([6835989](https://github.com/mr-pmillz/gophlare/commit/6835989954df85bda9222eae6eca69a741079095))

### ⚡ Performance

- Optimized flags parser - ([9b62902](https://github.com/mr-pmillz/gophlare/commit/9b629029ddbcfbbea6a1dee358fc715391d972c3))

## [1.3.1](https://github.com/mr-pmillz/gophlare/compare/v1.3.0...v1.3.1) - 2025-11-17

### ✨ New features

- Add sqlite integration - ([358cb2b](https://github.com/mr-pmillz/gophlare/commit/358cb2b9ae3121f2210aa6073fe4147ae8595396))

### ⚙️  Miscellaneous

- Stealer log db integration working poc - ([e05765a](https://github.com/mr-pmillz/gophlare/commit/e05765a20747c1758c69e4c0a7f79f63cab30931))
- Stealer log db integration checkpoint - ([6093607](https://github.com/mr-pmillz/gophlare/commit/609360762ac2ada47ac96d1d27137f4dac0d6358))
- Update changelog - ([214b73a](https://github.com/mr-pmillz/gophlare/commit/214b73aa30924961990ce6399f67c1d6604e4178))

## [1.3.0](https://github.com/mr-pmillz/gophlare/compare/v1.2.9...v1.3.0) - 2025-09-19

### ⚙️  Miscellaneous

- Replaced deprecated api endpoints
optimized hash filtering - ([32cf343](https://github.com/mr-pmillz/gophlare/commit/32cf3436cf80b49b1b8992c1c9112c007c156148))
- Update changelog - ([444c0ef](https://github.com/mr-pmillz/gophlare/commit/444c0ef570a19d251960ebd2faca68df17bd4340))

## [1.2.9](https://github.com/mr-pmillz/gophlare/compare/v1.2.8...v1.2.9) - 2025-08-20

### ⚙️  Miscellaneous

- Version bump - ([27d10b5](https://github.com/mr-pmillz/gophlare/commit/27d10b54b7b5fdf0de64d39548ef5826a7ac38e5))
- Changed domain to domains arg - ([cd12d3a](https://github.com/mr-pmillz/gophlare/commit/cd12d3a7f9b0162cd10e337a62942ce68f99ccd7))
- Update changelog - ([ae433c2](https://github.com/mr-pmillz/gophlare/commit/ae433c24dae3e95c9cdc8f95ccaaeb62aabdf25e))

## [1.2.8](https://github.com/mr-pmillz/gophlare/compare/v1.2.7...v1.2.8) - 2025-08-01

### ✨ New features

- Add wildcard host global event search option - ([cb36a65](https://github.com/mr-pmillz/gophlare/commit/cb36a65e6c443b0f90be25775735d12c438dc509))

### 🛠 Improvements

- Update docs - ([4144d53](https://github.com/mr-pmillz/gophlare/commit/4144d53a78713b6768442cd59d657655ac54a967))

### ⚙️  Miscellaneous

- Update changelog - ([1cf8ca2](https://github.com/mr-pmillz/gophlare/commit/1cf8ca29208514b752c78be9677da2316eaa8371))

## [1.2.7](https://github.com/mr-pmillz/gophlare/compare/v1.2.6...v1.2.7) - 2025-07-02

### 🐛 Bug fixes

- Fixed missing cmd loader for custom query :bug: - ([36183be](https://github.com/mr-pmillz/gophlare/commit/36183be856d57b0b26df8f95bc52be627c0e183a))

### 📚 Documentation

- Docs update - ([037483d](https://github.com/mr-pmillz/gophlare/commit/037483d6da174cbadcb7ea9913ab8a59c5a7b96a))

### ⚙️  Miscellaneous

- Update changelog - ([d19d4b0](https://github.com/mr-pmillz/gophlare/commit/d19d4b0d757889fbf06015674c0e04e801ef9201))

## [1.2.6](https://github.com/mr-pmillz/gophlare/compare/v1.2.5...v1.2.6) - 2025-06-14

### ✨ New features

- Added :rabbit2: additional leak data ingestors 4 bloodhound - ([2f4a6fa](https://github.com/mr-pmillz/gophlare/commit/2f4a6fa77657f7ab08d4b58582b6c49bce1d6c37))

### 📚 Documentation

- Docs update - ([d83b278](https://github.com/mr-pmillz/gophlare/commit/d83b278437dde73c3878f87bdcaa4bcbb9f67852))

### ⚙️  Miscellaneous

- Update changelog - ([0cb90ce](https://github.com/mr-pmillz/gophlare/commit/0cb90ce61d3106d4a5a7ca6c71db534bc1963f90))

## [1.2.5](https://github.com/mr-pmillz/gophlare/compare/v1.2.4...v1.2.5) - 2025-06-11

### ✨ New features

- Add Autofills.txt to stealerlog downloaded files - ([7d5720b](https://github.com/mr-pmillz/gophlare/commit/7d5720bdca0bd3c9991c07c8dbd95a9fedcdfb90))

### ⚙️  Miscellaneous

- Update changelog - ([81f0094](https://github.com/mr-pmillz/gophlare/commit/81f0094d559edc67cd05c3ee77ec9bcd2bd15fe8))

## [1.2.4](https://github.com/mr-pmillz/gophlare/compare/v1.2.3...v1.2.4) - 2025-05-23

### 📚 Documentation

- Docs update readme - ([c7502a5](https://github.com/mr-pmillz/gophlare/commit/c7502a5e2aa7ddda5ae8ed0ba601b555e8d3ef41))

### 🛠 Improvements

- Update readme - ([7ae3e4a](https://github.com/mr-pmillz/gophlare/commit/7ae3e4a705fe246f621a09f5ac822d2043946833))

### ⚙️  Miscellaneous

- :goat: increased verbosity :dog2: version bump - ([236c876](https://github.com/mr-pmillz/gophlare/commit/236c87645539fbb072b3d075126e03a9dfcce12f))
- Update changelog - ([04a1d8d](https://github.com/mr-pmillz/gophlare/commit/04a1d8db532a74bb0a1ac8f7063e0e9887013507))

## [1.2.3](https://github.com/mr-pmillz/gophlare/compare/v1.2.2...v1.2.3) - 2025-05-23

### 📚 Documentation

- Docs update readme - ([019bed9](https://github.com/mr-pmillz/gophlare/commit/019bed9b30ea7b951615ca6f80f867985edd95ce))
- Docs update - ([6258eac](https://github.com/mr-pmillz/gophlare/commit/6258eac8e2f79027f15127709bd7e8f0f6dce1a3))

### ⚙️  Miscellaneous

- Version bump - ([c43e923](https://github.com/mr-pmillz/gophlare/commit/c43e923e735857c51d8754d77ca8e6b6cef42c6e))
- Merge pull request #1 from mr-pmillz/bloodhound

Draft: Bloodhound integration - ([7a1bc94](https://github.com/mr-pmillz/gophlare/commit/7a1bc9494e4028f877f966a3aab434c0f804bdfe))
- Removed unused code and cleanup - ([1dff448](https://github.com/mr-pmillz/gophlare/commit/1dff4489241af13c685f7cde7ef49f566248a0d2))
- Bloodhound integration PoC shortest paths from breached credentials - ([a9c8ac5](https://github.com/mr-pmillz/gophlare/commit/a9c8ac504419b9e722da317362ea0685c45776b5))
- Resolved linter warnings - ([7034a62](https://github.com/mr-pmillz/gophlare/commit/7034a6223fb628f7ffbc6c0da010b5340b6f18c5))
- :cyclone: Completed Phase 2 :crystal_ball: - ([abcfa97](https://github.com/mr-pmillz/gophlare/commit/abcfa97d640a0d232237d2e1c7488b6c1ecf5983))
- Initial bloodhound integration testing - ([afca637](https://github.com/mr-pmillz/gophlare/commit/afca6375c6c49f84cd4b8360b7d420bcdcf07189))
- Update changelog - ([0198c65](https://github.com/mr-pmillz/gophlare/commit/0198c65794cb82d4110ddf4021e53e7ada2b6759))

## [1.2.2](https://github.com/mr-pmillz/gophlare/compare/v1.2.1...v1.2.2) - 2025-04-25

### ✨ New features

- Optimized cred parser to support redline format. various other improvements - ([5101242](https://github.com/mr-pmillz/gophlare/commit/5101242f8dc55bf545e9ab848bb330c67c93413d))

### ⚙️  Miscellaneous

- Update changelog - ([d61fbda](https://github.com/mr-pmillz/gophlare/commit/d61fbda0abc029f1fbf4cf0311a0f0bbe2bf26bc))

## [1.2.1](https://github.com/mr-pmillz/gophlare/compare/v1.2.0...v1.2.1) - 2025-04-22

### ✨ New features

- Added token refresh capabilities, updated lint config - ([58827c8](https://github.com/mr-pmillz/gophlare/commit/58827c85816634343251be6d0c5d22c381c40e4c))

### 📚 Documentation

- Docs update - ([ed832d8](https://github.com/mr-pmillz/gophlare/commit/ed832d8770ef8891494eae89e40bfe9f752bdedd))

### 📦 Dependencies

- Deps update - ([b719910](https://github.com/mr-pmillz/gophlare/commit/b719910136bb8276e355040593738503324b91ad))

### ⚙️  Miscellaneous

- Update changelog - ([fa667c5](https://github.com/mr-pmillz/gophlare/commit/fa667c57d2d265fc8e2b509e80f9d7c402656e0a))

## [1.2.0](https://github.com/mr-pmillz/gophlare/compare/v1.1.9...v1.2.0) - 2025-04-17

### 🐛 Bug fixes

- Write individual cookie bro and events json to files. resolved linter warnings - ([58dc8a0](https://github.com/mr-pmillz/gophlare/commit/58dc8a07b2e9a1c1bb84799cde69264989778a60))
- Fixed bufio.Scanner: token too long bug :bug: - ([0e0a172](https://github.com/mr-pmillz/gophlare/commit/0e0a172311abbbe2c35ff4294ddbcc46aa592ac0))
- Fixed flare events time.Time type unmarshalling bug :bug: - ([4a5ce83](https://github.com/mr-pmillz/gophlare/commit/4a5ce8363107472bcff1a7cfabdf54b66a6267f8))

### ⚡ Performance

- Optimized warning log msg fmt - ([ffbc4d6](https://github.com/mr-pmillz/gophlare/commit/ffbc4d6a6384c581fb9d3fd127b56d430006a4da))

### ⚙️  Miscellaneous

- Update changelog - ([686853f](https://github.com/mr-pmillz/gophlare/commit/686853f43ac8161a134e0db4551c187c4d0e0305))

## [1.1.9](https://github.com/mr-pmillz/gophlare/compare/v1.1.8...v1.1.9) - 2025-04-17

### ⚡ Performance

- Optimized. log warning instead of err to continue downloading results - ([0c0e24a](https://github.com/mr-pmillz/gophlare/commit/0c0e24ad873ff51c3ee40e33e0e31b391e39c06c))

### ⚙️  Miscellaneous

- Update changelog - ([e856eac](https://github.com/mr-pmillz/gophlare/commit/e856eace18174d4eeb2707c3a74958495c609fd8))

## [1.1.8](https://github.com/mr-pmillz/gophlare/compare/v1.1.7...v1.1.8) - 2025-04-09

### 🛠 Improvements

- Updated goreleaser dockerfile and docs - ([21ff4a1](https://github.com/mr-pmillz/gophlare/commit/21ff4a1f8cf1f9dad8ec0e41d375aec8e939bfb0))

### ⚙️  Miscellaneous

- Update README.md - ([bac3169](https://github.com/mr-pmillz/gophlare/commit/bac3169074132da65402b34c4e0361cdbac07364))
- Update changelog - ([53eee49](https://github.com/mr-pmillz/gophlare/commit/53eee49af00085e4e62be8e9ce27f68680b2758e))

## [1.1.7](https://github.com/mr-pmillz/gophlare/compare/v1.1.6...v1.1.7) - 2025-03-12

### 🛠 Improvements

- Update cicd permissions in ci.yml - ([e3f1b86](https://github.com/mr-pmillz/gophlare/commit/e3f1b862b87a2348272ce501123c0ced2d65b51a))

## [1.1.6](https://github.com/mr-pmillz/gophlare/compare/v1.1.5...v1.1.6) - 2025-03-12

### ✨ New features

- Add GITHUB_TOKEN to .goreleaser env for ghcr push - ([4a2dcf8](https://github.com/mr-pmillz/gophlare/commit/4a2dcf894a9e52b90f9efe43bc1cf39b280d9d1c))

## [1.1.5](https://github.com/mr-pmillz/gophlare/compare/v1.1.4...v1.1.5) - 2025-03-12

### 🧪 Testing

- Testing goreleaser docker build/push to ghcr.io - ([1b7c003](https://github.com/mr-pmillz/gophlare/commit/1b7c0030d26c9112da4ef696b708fdf002675783))

## [1.1.4](https://github.com/mr-pmillz/gophlare/compare/v1.1.3...v1.1.4) - 2025-03-12

### ⚙️  Miscellaneous

- Map has no entry for key "Arch", i knew it! - ([ebb2393](https://github.com/mr-pmillz/gophlare/commit/ebb23930271a0816eb7d91c8780d7bcc46e8bb41))

## [1.1.3](https://github.com/mr-pmillz/gophlare/compare/v1.1.2...v1.1.3) - 2025-03-12

### ✨ New features

- Added Dockerfile & updated goreleaser to push image to ghcr.io - ([b4428d1](https://github.com/mr-pmillz/gophlare/commit/b4428d17f2fcbd0b5cb7bab0529e445f0014f625))

### ⚙️  Miscellaneous

- Update README.md - ([c204f38](https://github.com/mr-pmillz/gophlare/commit/c204f382ea0eaad514b5d6a7ed94223d4b733aec))
- Update changelog - ([fc0a26e](https://github.com/mr-pmillz/gophlare/commit/fc0a26e8aad90b352793453a2356094cf56e20e3))

## [1.1.2](https://github.com/mr-pmillz/gophlare/compare/v1.1.1...v1.1.2) - 2025-03-10

### 🛠 Improvements

- Update changelog - ([78496b6](https://github.com/mr-pmillz/gophlare/commit/78496b6a4490beb64ecdaf368c5a491c42678a36))

### ⚙️  Miscellaneous

- Changelog generation handled by cicd... - ([86e1ef6](https://github.com/mr-pmillz/gophlare/commit/86e1ef60a869d72562f452dc3413aa7288703a1f))

## [1.1.1](https://github.com/mr-pmillz/gophlare/compare/v1.1.0...v1.1.1) - 2025-03-10

### ✨ New features

- Added NewConfig helper, updated NewScope, version bump - ([5705ddd](https://github.com/mr-pmillz/gophlare/commit/5705ddddaf4ff13372a94ce94ce314397947c2f4))

### 🛠 Improvements

- Update README.md added badges - ([04d8c7a](https://github.com/mr-pmillz/gophlare/commit/04d8c7a75c1fc6520372577aaf2722a4da05f7e5))

### ⚙️  Miscellaneous

- Update changelog - ([3f49bfc](https://github.com/mr-pmillz/gophlare/commit/3f49bfc2d2abfc01531aa0f85ba5923ccda8982e))

## [1.1.0](https://github.com/mr-pmillz/gophlare/compare/v1.0.9...v1.1.0) - 2025-02-20

### ✨ New features

- Added from, to, severity, eventsFilterTypes opts
- refactored search command
- updated docs - ([52e632e](https://github.com/mr-pmillz/gophlare/commit/52e632e7075ab4c822285702f0bcbb886fc9767a))

### ⚙️  Miscellaneous

- Update changelog - ([6a59d0a](https://github.com/mr-pmillz/gophlare/commit/6a59d0a036e9a19fcaa463a08d1b34cc854ca547))

## [1.0.9](https://github.com/mr-pmillz/gophlare/compare/v1.0.8...v1.0.9) - 2025-02-19

### 🐛 Bug fixes

- Fixed :bug: in --search-emails-in-bulk - ([0925622](https://github.com/mr-pmillz/gophlare/commit/0925622c38a43384892baccdc7ba5f14f38def56))

### 🛠 Improvements

- Update readme version bump - ([e63851d](https://github.com/mr-pmillz/gophlare/commit/e63851df8cea21fa44d68f1e9336a173afca8f05))
- Update readme - ([95769ed](https://github.com/mr-pmillz/gophlare/commit/95769ed553b212a1d813d442e1d7a6a141444d7e))

### ⚙️  Miscellaneous

- Update changelog - ([c1200d4](https://github.com/mr-pmillz/gophlare/commit/c1200d4fccff442c5c860ce83d5927220ba68d5f))

## [1.0.8](https://github.com/mr-pmillz/gophlare/compare/v1.0.7...v1.0.8) - 2025-02-17

### 🛠 Improvements

- Update readme - ([b0d22b8](https://github.com/mr-pmillz/gophlare/commit/b0d22b8d25da39cb85bc6f326c125b39d8d218db))

### ⚙️  Miscellaneous

- Merge branch 'main' of github.com:mr-pmillz/gophlare - ([3ff7612](https://github.com/mr-pmillz/gophlare/commit/3ff7612ee294007b4c8c99e1ce77ab67dd8c96d0))
- Update changelog - ([51ef9cb](https://github.com/mr-pmillz/gophlare/commit/51ef9cb93c468c41bcac82ac12cf11e6dd169377))

## [1.0.7](https://github.com/mr-pmillz/gophlare/compare/v1.0.6...v1.0.7) - 2025-02-16

### 🐛 Bug fixes

- Fix typo in options.go for user-id-format flag - ([69a541b](https://github.com/mr-pmillz/gophlare/commit/69a541bd607886b1f5ab6d3c1d2f982acd2c0a1c))

## [1.0.6](https://github.com/mr-pmillz/gophlare/compare/v1.0.5...v1.0.6) - 2025-02-16

### 🐛 Bug fixes

- Fix goreleaser :bug: dirty state update .gitignore job version bump - ([44e4f48](https://github.com/mr-pmillz/gophlare/commit/44e4f485670c48df5bf3e5d6eecb830703b04232))

## [1.0.5](https://github.com/mr-pmillz/gophlare/compare/v1.0.4...v1.0.5) - 2025-02-16

### 🛠 Improvements

- Update cicd goreleaser job version bump - ([7754301](https://github.com/mr-pmillz/gophlare/commit/77543019b818dde9ef0e221cce14c2741bf5b5a2))

### ⚙️  Miscellaneous

- Update changelog - ([844e9bf](https://github.com/mr-pmillz/gophlare/commit/844e9bf49978bd53a5454602f9c730abf786c205))

## [1.0.4](https://github.com/mr-pmillz/gophlare/compare/v1.0.3...v1.0.4) - 2025-02-16

### 🛠 Improvements

- Update cicd goreleaser job version bump - ([788e8f2](https://github.com/mr-pmillz/gophlare/commit/788e8f28b9e8dd3c6cdbcd1897f42df54d72af8a))

## [1.0.3](https://github.com/mr-pmillz/gophlare/compare/v1.0.2...v1.0.3) - 2025-02-16

### 🛠 Improvements

- Update go.mod - ([47d29b3](https://github.com/mr-pmillz/gophlare/commit/47d29b34934d80ffc0aee526449753af23939134))

## [1.0.2](https://github.com/mr-pmillz/gophlare/compare/v1.0.1...v1.0.2) - 2025-02-16

### 🛠 Improvements

- Update pre-commit-config.yaml - ([11c5a7e](https://github.com/mr-pmillz/gophlare/commit/11c5a7e82f27462ed88dc28e0382f337d1ed0b92))
- Update cicd goreleaser job version bump - ([d1b5e6b](https://github.com/mr-pmillz/gophlare/commit/d1b5e6bd604394cd7c362ea8f09011ffe5a50be6))
- Update cliff.toml - ([fa8648b](https://github.com/mr-pmillz/gophlare/commit/fa8648bc8a872581386ca56ac20df94c75d4aa1c))

### ⚙️  Miscellaneous

- Update changelog - ([a45ff4f](https://github.com/mr-pmillz/gophlare/commit/a45ff4f1e0dfd9b3e5366da1687aaf1312c8b359))

## [1.0.1](https://github.com/mr-pmillz/gophlare/compare/v1.0.0...v1.0.1) - 2025-02-16

### ✨ New features

- Added cookies/_search api and optimized thangs :cookie: - ([d3aecf2](https://github.com/mr-pmillz/gophlare/commit/d3aecf2feceea3d5a4080f191953458ff14b7e9c))

## [1.0.0] - 2025-02-16

### ✨ New features

- Add git-cliff changelog and ci job - ([2a8464a](https://github.com/mr-pmillz/gophlare/commit/2a8464af53b6cfb2641da3780dd768ba36bbe87a))

### 🐛 Bug fixes

- First commit - ([322f252](https://github.com/mr-pmillz/gophlare/commit/322f252f691a024711a08a0618eb1d9d0704f5ae))

### ⚙️  Miscellaneous

- Initial poc rough draft.. ToDo: cookie logic code-review - ([d8acda9](https://github.com/mr-pmillz/gophlare/commit/d8acda9e826250603d472ea4151f93ffc4021c33))

<!-- generated by git-cliff -->
