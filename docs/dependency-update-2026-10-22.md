# Dependency update — 2026-10-22

This records the initial dependency refresh. The [CI remediation follow-up](#ci-remediation-follow-up)
supersedes the original Excelize exception and addresses the missing spec inputs.

Checked all 17 direct Go modules against the Go module proxy and all 14 distinct
GitHub Actions against their upstream release tags. Targets stay on their
existing module paths, major versions, and release channels. The other 15 Go
modules and 10 actions are already current within those constraints. No release
cooldown is configured in `.github/dependabot.yml`.

## Updates

| Dependency | Previous | Updated |
| --- | --- | --- |
| `github.com/gocarina/gocsv` | `v0.0.0-20260523204920-c264028e67ea` | `v0.0.0-20261012193826-401c25af6907` |
| `github.com/oapi-codegen/nullable` | `v1.1.0` | `v1.2.0` |
| `actions/create-github-app-token` | `v3.2.0` | `v3.3.0` |
| `actions/upload-artifact` | `v7.0.1` | `v7.0.2` |
| `actions/download-artifact` | `v8.0.1` | `v8.0.2` |
| `goreleaser/goreleaser-action` | `v7.2.3` | `v7.3.0` |

All four action updates match [Dependabot PR #31](https://github.com/mr-pmillz/gophlare/pull/31).
Its seven pin sites across four workflows now use the verified full upstream
commit SHAs. Existing triggers, permissions, inputs, and tool versions are
unchanged. In particular, the GoReleaser wrapper still installs GoReleaser
`v2.13.3`. The PR has not been merged or closed.

The module updates were applied with exact-version `go get` and `go mod tidy`,
using `GOTOOLCHAIN=local` and Go `1.27.3`. No indirect requirements or toolchain
settings changed.

## Compatibility and security verdict

- [GoCSV's changes](https://github.com/gocarina/gocsv/compare/c264028e67ea...401c25af6907)
  fix decoding/marshalling panics, nested-field handling, callback cleanup, and
  numeric conversion. Integer CSV fields now use decimal rather than base-0
  parsing, and overflowing values return errors instead of wrapping. Regression
  tests cover these changes, quoted/multiline Unicode CSV, large IDs, and Excel
  export readback. The application's credential CSV fields remain strings.
- [Nullable v1.2.0](https://github.com/oapi-codegen/nullable/releases/tag/v1.2.0)
  adds `GetOrEmpty` without changing existing JSON semantics. Existing generated
  model tests still preserve omitted, null, explicit false, and empty values.
- The [upload](https://github.com/actions/upload-artifact/releases/tag/v7.0.2)
  and [download](https://github.com/actions/download-artifact/releases/tag/v8.0.2)
  patches improve artifact-service throttling retries. The
  [token action](https://github.com/actions/create-github-app-token/releases/tag/v3.3.0)
  updates dependencies and permission inputs; its removed team-discussions
  input is not used here. The
  [GoReleaser action](https://github.com/goreleaser/goreleaser-action/releases/tag/v7.3.0)
  adds tool-cache reuse and dependency updates. These are maintenance and
  defensive updates, not a demonstrated fix for a repository-specific exploit.

### Unresolved Excelize advisories

**Security gate: blocked by pre-existing findings.** Excelize `v2.11.0` is still
the latest stable release. CI's `govulncheck -scan=package ./...` reports six
advisories both before and after these updates:
[GO-2026-6695](https://pkg.go.dev/vuln/GO-2026-6695),
[GO-2026-6689](https://pkg.go.dev/vuln/GO-2026-6689),
[GO-2026-6688](https://pkg.go.dev/vuln/GO-2026-6688),
[GO-2026-6687](https://pkg.go.dev/vuln/GO-2026-6687),
[GO-2026-6685](https://pkg.go.dev/vuln/GO-2026-6685), and
[GO-2026-6684](https://pkg.go.dev/vuln/GO-2026-6684).

Symbol-level scans also report GO-2026-6688 and GO-2026-6684 on both dependency
graphs. Their triggers involve cyclic array formulas and malformed encrypted
workbooks. Production code creates new workbooks from CSV rather than opening
external XLSX files, but this review does not establish that the scan findings
are unexploitable. No advisory is suppressed and the CI gate is unchanged.

Upstream development version `v2.11.1-0.20261020033641-611b222fd8f7` contains all
six fixes, as verified against the
[upstream changes](https://github.com/qax-os/excelize/compare/v2.11.0...611b222fd8f78863a9932529340ebe03ebc8f237).
It requires Go 1.26, which this project satisfies. Switching from a stable tag
to this unreleased version requires an explicit release-channel decision and
has not been applied without approval.

The previously recorded [OpenPGP advisory](https://pkg.go.dev/vuln/GO-2026-5932)
remains module-only; `go list -deps ./...` confirms that no affected OpenPGP
package is imported.

### Workflow review

**Pass-with-warnings.** All action references remain SHA-pinned, and parsed
workflow comparisons confirm that only action references changed. Reviewed
scanner candidates retain their existing guards: untrusted branch values use
quoted environment variables, write-capable jobs retain their trigger guards,
and OIDC remains used for artifact attestations. External repository
rulesets, App grants, and hosted release execution were not verified locally.

## Validation

- Full `go test -race -count=1 ./...` suite and focused CSV/nullable tests pass.
- `make fmt`, `go vet ./...`, and configured golangci-lint v2.14.0 pass.
- `go mod verify` and `go mod tidy -diff` pass.
- `make generate` produces no changes to generated API code.
- Linux and macOS builds pass for both amd64 and arm64 with CGO disabled.
- All workflow YAML parses; actionlint v1.7.12 passes with the documented
  `code-quality` permission exception; all three release-policy tests pass.
- Package and symbol vulnerability checks retain the Excelize failures above.
  The scanner was rebuilt in a temporary directory with Go 1.27.3 because the
  existing global binary was built with Go 1.26.5.

Release publication and Docker builds were not run. No remote PR changes were
made. The earlier [security review](dependency-security.md) remains historical.

## CI remediation follow-up

[Run 39866826398](https://github.com/mr-pmillz/gophlare/actions/runs/39866826398)
failed generation, coverage tests, and vulnerability scanning; `CI checks`
correctly failed because it depends on those jobs. Public job metadata and
clean-source reproductions identified two causes:

- The root `*.json` ignore rule excluded all three Firework OpenAPI inputs.
  A tracked-files-only export failed `make generate` with missing-spec errors
  and failed `TestOperationsMatchSpecs` for the same reason. The three public
  snapshots are now included with exact root-level ignore exceptions. Their
  JSON content matches Flare's published specs, and generation does not change
  the checked-in clients. Regression tests verify snapshot availability and
  keep unrelated JSON output and tenant configuration ignored.
- With explicit approval, Excelize is pinned to
  `v2.11.1-0.20261020033641-611b222fd8f7` rather than the vulnerable stable tag.
  Go's module tooling also selects its required `mscfb v1.0.8`, `efp v0.0.2`,
  and `x/image v0.44.0`. The project stays on Go 1.27.3. Both package- and
  symbol-level scans now report zero affected vulnerabilities; the unrelated,
  unimported OpenPGP module advisory remains visible without failing either
  check. No security gate or advisory suppression was added.

Validation uses a fresh source snapshot containing only Git-visible files,
not the original checkout's ignored inputs. Generation, build, module checks,
full race/coverage tests, and all five repository-policy tests pass. The patched
Excelize version also passes CSV-to-XLSX export/readback, vet, golangci-lint,
and all four release-target builds. Workflow lint passes with the existing
documented permission-scope exception; workflow execution and permissions are
unchanged apart from renaming the policy-test step to reflect its broader tests.

These are local validation results, not a successful rerun of the hosted jobs.
The fixes must reach the PR branch before GitHub can validate them.
