# Dependency security review — 2026-09-12

Go is pinned to **1.26.6** in `go.mod` and the Docker builder. CI and release
workflows read `go.mod`. Module upgrades were resolved with `GOTOOLCHAIN=local`
using Go 1.26.6, without a newer toolchain override.

| Module | Previous | Updated | Minimum fixing all listed alerts |
| --- | --- | --- | --- |
| `golang.org/x/crypto` | v0.48.0 | **v0.57.0** | v0.52.0 |
| `golang.org/x/net` | v0.50.0 | **v0.59.0** | v0.55.0 |
| `github.com/getkin/kin-openapi` | v0.135.0 | **v0.149.0** | v0.144.0 |
| `github.com/xuri/excelize/v2` | v2.10.1 | **v2.11.0** | v2.11.0 |
| `github.com/oapi-codegen/oapi-codegen/v2` | v2.7.0 | **v2.8.0** | v2.7.1 |

GitHub’s public advisory API returned zero matching advisories for each updated
version. The repository-specific Dependabot API returned HTTP 403 with the
available token; the 22 alert numbers below come from the supplied alert list.
GitHub will reevaluate the alerts when the updated manifest reaches the default
branch. No alerts were dismissed or repository settings changed.

## Alert mapping

| Alert | Module | Advisory |
| --- | --- | --- |
| #13 | `golang.org/x/net` | [GHSA-5cv4-jp36-h3mw](https://github.com/advisories/GHSA-5cv4-jp36-h3mw) |
| #14 | `golang.org/x/crypto` | [GHSA-rm3j-f69w-wqmq](https://github.com/advisories/GHSA-rm3j-f69w-wqmq) |
| #15 | `golang.org/x/crypto` | [GHSA-w879-237q-wc7r](https://github.com/advisories/GHSA-w879-237q-wc7r) |
| #16 | `golang.org/x/crypto` | [GHSA-45gg-vh54-h5m9](https://github.com/advisories/GHSA-45gg-vh54-h5m9) |
| #17 | `golang.org/x/crypto` | [GHSA-x527-x647-q7gg](https://github.com/advisories/GHSA-x527-x647-q7gg) |
| #18 | `golang.org/x/crypto` | [GHSA-q4h4-gmj2-qvw2](https://github.com/advisories/GHSA-q4h4-gmj2-qvw2) |
| #19 | `golang.org/x/crypto` | [GHSA-89gr-r52h-f8rx](https://github.com/advisories/GHSA-89gr-r52h-f8rx) |
| #20 | `golang.org/x/crypto` | [GHSA-5cgq-3rg8-m6cv](https://github.com/advisories/GHSA-5cgq-3rg8-m6cv) |
| #21 | `golang.org/x/crypto` | [GHSA-f5wc-c3c7-36mc](https://github.com/advisories/GHSA-f5wc-c3c7-36mc) |
| #22 | `golang.org/x/crypto` | [GHSA-9m57-25v3-79x9](https://github.com/advisories/GHSA-9m57-25v3-79x9) |
| #23 | `golang.org/x/crypto` | [GHSA-vgwf-h737-ff37](https://github.com/advisories/GHSA-vgwf-h737-ff37) |
| #24 | `golang.org/x/crypto` | [GHSA-jppx-rxg9-jmrx](https://github.com/advisories/GHSA-jppx-rxg9-jmrx) |
| #25 | `golang.org/x/crypto` | [GHSA-78mq-xcr3-xm33](https://github.com/advisories/GHSA-78mq-xcr3-xm33) |
| #26 | `golang.org/x/crypto` | [GHSA-qpw4-5x99-6vjp](https://github.com/advisories/GHSA-qpw4-5x99-6vjp) |
| #27 | `github.com/xuri/excelize/v2` | [GHSA-h69g-9hx6-f3v4](https://github.com/advisories/GHSA-h69g-9hx6-f3v4) |
| #28 | `github.com/oapi-codegen/oapi-codegen/v2` | [GHSA-rjwr-m7qx-3fjr](https://github.com/advisories/GHSA-rjwr-m7qx-3fjr) |
| #29 | `github.com/getkin/kin-openapi` | [GHSA-r277-6w6q-xmqw](https://github.com/advisories/GHSA-r277-6w6q-xmqw) |
| #30 | `github.com/getkin/kin-openapi` | [GHSA-jpcw-4wr7-c3vq](https://github.com/advisories/GHSA-jpcw-4wr7-c3vq) |
| #31 | `github.com/getkin/kin-openapi` | [GHSA-xhj3-7xw9-vr34](https://github.com/advisories/GHSA-xhj3-7xw9-vr34) |
| #32 | `github.com/getkin/kin-openapi` | [GHSA-mmfr-pmjx-hw9w](https://github.com/advisories/GHSA-mmfr-pmjx-hw9w) |
| #33 | `github.com/xuri/excelize/v2` | [GHSA-fx5j-qcqg-grpf](https://github.com/advisories/GHSA-fx5j-qcqg-grpf) |
| #34 | `github.com/xuri/excelize/v2` | [GHSA-q5j5-6p94-4gwc](https://github.com/advisories/GHSA-q5j5-6p94-4gwc) |

## Additional scan findings

`github.com/klauspost/compress` was also upgraded from v1.18.2 to **v1.18.7**,
fixing the S2 dictionary out-of-bounds read described by
[GO-2026-5841](https://pkg.go.dev/vuln/GO-2026-5841).

`govulncheck -scan=package ./...` reports **no vulnerabilities in imported
packages**. The module scan still reports
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), covering the deprecated
`golang.org/x/crypto/openpgp` packages across all versions with no fixed release.
`go list -deps ./...` confirms that none of these packages are imported.
The required `x/crypto` module also provides unrelated packages used by the
application, so replacing the whole module with an OpenPGP fork would be wrong.

CI runs the package-level scan as part of `CI checks`; importing an affected
OpenPGP package in a future change will fail that check. The advisory is not
suppressed. The scanner is pinned to govulncheck v1.6.0, which supports Go 1.26.6.

## Validation

- Full Go test suite passed with race detection on Go 1.26.6.
- golangci-lint: zero issues.
- Module tidy/integrity checks and application build passed.
- CSV-to-Excel export/readback passed with Excelize 2.11.0.
- CLI success and failure paths wrote metrics to the configured output directory.
- Workflow lint, release policy tests, and GoReleaser configuration checks passed.

Release publication and Docker image builds were not executed. Changes remain
local until the branch is committed and pushed.
