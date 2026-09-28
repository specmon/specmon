# Contributing to SpecMon

Thank you for your interest in contributing to SpecMon! This guide will help you get started.

## Development Setup

### Standard Go Setup

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/specmon.git
   cd specmon
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/specmon/specmon.git
   ```
4. Ensure you have Go 1.21 or later installed
5. Download dependencies:
   ```bash
   go mod download
   ```
6. Build the project:
   ```bash
   go build
   ```

### Alternative: Nix Development Environment

If you have Nix with flakes enabled, you can use our reproducible environment:

```bash
nix develop
```

This provides all dependencies and tools automatically.

## Making Changes

1. Create a descriptive branch from `develop`. A good practice is to name it `type/short-description` (e.g., `feat/add-yaml-support` or `fix/parser-bug`).
   ```bash
   git fetch upstream
   git checkout -b feat/add-yaml-support upstream/develop

2. Make your changes following our coding standards:
   - Run `go fmt` before committing
   - Follow [Effective Go](https://golang.org/doc/effective_go.html) conventions
   - Include tests for any new functionality or bug fixes.

3. Commit using [Conventional Commits](https://conventionalcommits.org):
   ```bash
   git commit -m "feat(parser): Add new capability"
   git commit -m "fix(monitor): Resolve issue with X"
   git commit -m "chore: Update Dependencies"
   ```

   Keep the subject line at most 72 characters, not counting the
   `(#123)` suffix that GitHub appends on squash merges. Write it in
   imperative mood and capitalize the first word after the colon. Leave
   a blank line after the subject and hard wrap the body at 72
   characters. The same applies to squash commit messages edited on
   GitHub.

   `gitlint`, included in the Nix dev shell, checks these rules, and CI
   runs it on the commits of every pull request. To check each commit
   locally, install its hook with `gitlint install-hook`.

4. Push to your fork and create a pull request against `develop`

## Code Quality

- Use `go fmt` to format your code
- Follow standard Go naming conventions
- Write clear, descriptive commit messages
- Keep changes focused and atomic

## Releasing a New Version

SpecMon uses [Release Please](https://github.com/googleapis/release-please) and
[GoReleaser](https://goreleaser.com) for automated releases.

### How the pipeline works

1. Every push to `develop` triggers the Release Please workflow. It reads commit
   history since the last release and opens (or updates) a **Release PR** titled
   `chore(develop): Release X.Y.Z`.
2. The Release PR contains an updated `CHANGELOG.md` and a bump to
   `.release-please-manifest.json`.
3. When a maintainer merges the Release PR, Release Please creates a git tag
   (`vX.Y.Z`) and a GitHub Release with the changelog as the release body.
4. The same workflow then runs GoReleaser on a macOS runner, which builds binaries
   for `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`, attaches
   the archives and `checksums.txt` to the release, and publishes it. Each archive
   contains `LICENSE` and `THIRD_PARTY_LICENSES.txt`, which
   `make third-party-licenses` generates.

### What maintainers do

- Ensure all commits to `develop` follow [Conventional Commits](https://conventionalcommits.org).
  Release Please determines the next version automatically:
  - `fix:` → patch (0.1.0 → 0.1.1)
  - `feat:` → minor (0.1.0 → 0.2.0)
  - `feat!:` or `BREAKING CHANGE:` → minor while version < 1.0.0; major once ≥ 1.0.0
- Before merging the Release PR, check the open Dependabot alerts in the Security
  tab and resolve them on `develop`.
- Review the Release PR's `CHANGELOG.md` diff before merging.
- After the release is published, fast-forward `main` to the release tag:
  `git push upstream 'vX.Y.Z^{commit}:refs/heads/main'`.

### Do not edit manually

`CHANGELOG.md` and `.release-please-manifest.json` are managed automatically by
Release Please. Do not edit them by hand. The one exception is the release date,
which Release Please sets when it generates the Release PR: if the PR is merged
on a later day, correct the date in `CHANGELOG.md` and in the PR body.

### Version in dev builds

`specmon --version` prints `dev` for binaries built with `go build .`.
Release builds print the release version (e.g., `0.3.0`) via GoReleaser ldflags.

## Need Help?

If you have a question or need help, please [open a discussion](https://github.com/specmon/specmon/discussions) instead of an issue. This helps us keep the issue tracker focused on bugs and feature requests.