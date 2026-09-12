# Contributing to gophlare

Send feature, fix, dependency, and documentation PRs to `develop`. Use `feat/*`,
`feature/*`, or `fix/*` branches. Keep API keys, leaked credentials, cookies,
private target data, and tenant identifiers out of issues and test fixtures.

Run `make fmt`, `make lint`, `make test`, and `make build`. Go 1.26.6 comes from
`go.mod`; CI uses golangci-lint v2.12.2. Tests use local fixtures and mock servers,
without a Flare subscription. `make test` creates coverage output and runs the
race detector. Builds do not rewrite module files or global Go configuration.

CI runs for every PR into `develop`, `main`, release, or hotfix branches, and
for pushes to those branches. There are no path filters: documentation and
workflow PRs also receive required checks. `CI checks` requires build, lint,
race/coverage tests, and imported-package vulnerability scanning to pass. Workflow lint uses actionlint v1.7.12; its one
known diagnostic for the newer `code-quality` permission is excluded while all
other validation remains enabled. Coverage artifacts are available on forks;
GitHub test annotations and native coverage comparison are published separately
for repository PRs (except Dependabot, whose token is read-only), with the coverage baseline refreshed on `main` pushes.

`govulncheck -scan=package ./...` checks all imported packages, even when a
vulnerable function is not called. The module-only scan additionally reports
GO-2026-5932 for deprecated OpenPGP code inside `x/crypto`; gophlare does not
import that package. See [the dependency review](docs/dependency-security.md).

## Releasing

1. Cut `release/vX.Y.Z` from `develop`, or `hotfix/vX.Y.Z` from `main`. Stable
   versions only; the `v` in the branch name is optional. Prerelease branches
   and tags are rejected to avoid publishing prereleases as `latest`.
2. Update `version` in `cmd/root.go` and `gophlareClientVersion` in
   `phlare/flareClient.go` to `vX.Y.Z`. Update docs and relevant release notes.
3. Push the branch. Changelog automation generates a verified GitHub App commit.
   Review the generated changelog before merging. The workflow refuses to
   overwrite a newer branch commit; a concurrent push gets its own run.
4. Open a PR into `main`. After merge, Tag Release creates the version tag at
   that PR's exact merge commit. An existing tag is accepted only when it
   points at that commit; a conflicting tag fails without moving it.
5. The tag starts Release, which reruns CI against the tagged commit before
   publishing GoReleaser archives, checksums, archive provenance, and amd64/arm64
   GHCR images. Both version and `latest` container tags have multiarch manifests.
6. Open a PR from `main` back into `develop` to carry the release/hotfix and
   changelog forward. Merge commits preserve the shared release history.

`develop` → `main` PRs are also allowed, matching the reference repository's
policy, but do not automatically tag or publish. Use a release/hotfix branch
when you want a release. Manual stable tags must match both version strings
and point to a commit in `main`. To retry a failed publication after a tag was
created, rerun its Release workflow; rerunning Tag Release leaves existing tags
alone.

## GitHub setup

The repository files implement automation; GitHub settings and secrets must
also be configured by a repository administrator. No credentials belong in Git.

- Install a GitHub App on **gophlare** with repository **Contents: read/write**
  and **Pull requests: read**. Add its client ID as `GOPHLARE_APP_CLIENT_ID` and private
  key as `GOPHLARE_APP_PRIVATE_KEY` in Actions secrets. Workflow tokens are
  narrowed to this repository and only the permissions needed by each job.
  The App authenticates release-note generation, changelog commits, and release
  tag creation.
  App-created tags trigger Release; a tag created using `GITHUB_TOKEN` would
  not normally trigger another workflow ([GitHub documentation](https://docs.github.com/en/actions/concepts/security/github_token)).
- The existing `main` and `develop` rulesets already require PRs, signed
  commits, resolved conversations, and Code Owner review, and prevent deletion
  and force pushes. Add required checks **`CI checks`** and
  **`check-branch-policy`** to both rulesets, selecting GitHub Actions as their
  source. Keep merge commits enabled for this release flow. Deploy the workflow
  files to both branches before making those check names mandatory.
- Protect `release/*` and `hotfix/*` against force pushes and require signed
  commits, matching the reference repository. If you also require PRs on these
  branches, permit the scoped App to write its changelog commits. The App does
  not need to bypass `main` or `develop` protections.
- Restrict creation/update/deletion of `v*` tags to release maintainers and the
  App. Release jobs execute trusted tagged code with publishing permissions;
  branch policy alone does not protect manual tag creation.
- Allow the repository's `GITHUB_TOKEN` to publish to its GHCR package. Existing
  packages may need this repository added under their Actions access settings.
  The release workflow grants package writes only to its publishing job.

The public ruleset API was inspected on 2026-09-12: `main` and `develop` had
no required status checks, and no release/hotfix ruleset was present. The
maintainer confirmed the App secrets are configured; live App authentication
has not been exercised locally.
