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

4. Push to your fork and create a pull request against `develop`

## Code Quality

- Use `go fmt` to format your code
- Follow standard Go naming conventions
- Write clear, descriptive commit messages
- Keep changes focused and atomic

## Need Help?

If you have a question or need help, please [open a discussion](https://github.com/specmon/specmon-go/discussions) instead of an issue. This helps us keep the issue tracker focused on bugs and feature requests.