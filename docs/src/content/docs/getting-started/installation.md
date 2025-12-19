---
title: Installation
description: Complete guide to installing SpecMon
---

This guide will help you install SpecMon and get it running on your system.

## Prerequisites

Before installing SpecMon, ensure you have the following prerequisites installed:

### Required software

- **Go 1.21.4+** - SpecMon is written in Go and requires a recent version
  - Download from [go.dev](https://go.dev/)
  - Verify installation: `go version`

- **Git** - For cloning the repository and managing dependencies
  - Download from [git-scm.com](https://git-scm.com/)
  - Verify installation: `git --version`

### Optional dependencies

- **Tamarin** - For formal verification (optional)
  - Download from [tamarin-prover.github.io](https://tamarin-prover.github.io/)
  - Used for specification verification but not required for runtime monitoring

## Installation methods

### Method 1: from source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/specmon/specmon.git
   cd specmon
   ```

2. **Build the application:**
   ```bash
   make build
   ```

   Or alternatively:
   ```bash
   go build .
   ```

3. **Verify the installation:**
   ```bash
   ./specmon --version
   ```

### Method 2: development setup with Nix

If you're using Nix, you can set up the complete development environment:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/specmon/specmon.git
   cd specmon
   ```

2. **Enter the Nix development shell:**
   ```bash
   nix develop
   ```

   This provides all necessary dependencies including Go, development tools, and linters.

3. **Build the application:**
   ```bash
   go build
   ```

## Installation verification

To verify that SpecMon is correctly installed:

1. **Check version:**
   ```bash
   ./specmon --version
   ```

2. **Display help:**
   ```bash
   ./specmon --help
   ```

   You should see output similar to:
   ```
   SpecMon is a runtime specification monitor using multiset-rewrite rules

   Usage:
     specmon [flags]
     specmon [command]

   Available Commands:
     completion  Generate the autocompletion script for the specified shell
     help        Help about any command
     monitor     monitor the event trace

   Flags:
     -c, --cpu-profile-path string   cpu profile path
     -d, --decompose                 decompose rules (default true)
     -h, --help                      help for specmon
     -l, --log-level string          log level (default "error")
     -m, --mem-profile-path string   memory profile path
     -q, --quiet                     quiet output
     -r, --role string               role
     -s, --spec-path string          specification path
     -v, --verbose                   verbose output
         --version                   version for specmon
   ```

3. **Test with a sample specification:**

   See the [Quick Start](/getting-started/quick-start/) guide for a complete example.

## System integration

### Add to PATH (optional)

To use SpecMon from anywhere in your system, add the directory containing the binary to your PATH:

**Linux/macOS (Bash):**
```bash
# Add to your shell configuration
echo 'export PATH="$PATH:$HOME/path/to/specmon"' >> ~/.bashrc
source ~/.bashrc
```

**macOS (ZSH):**
```bash
echo 'export PATH="$PATH:$HOME/path/to/specmon"' >> ~/.zshrc
source ~/.zshrc
```

### Shell completion (optional)

Enable shell completion for better command-line experience:

**Bash:**
```bash
./specmon completion bash > /tmp/specmon_completion.bash
sudo mv /tmp/specmon_completion.bash /etc/bash_completion.d/
```

**ZSH:**
```bash
./specmon completion zsh > "${fpath[1]}/_specmon"
```

**Fish:**
```bash
./specmon completion fish > ~/.config/fish/completions/specmon.fish
```

## Troubleshooting

### Common issues

**Go version too old:**
```
Error: go: version "go1.20" does not match go tool version "go1.21.4"
```
*Solution:* Upgrade to Go 1.21.4 or later

**Permission denied:**
```
Error: permission denied: ./specmon
```
*Solution:* Make the binary executable: `chmod +x specmon`

**Missing dependencies:**
```
Error: cannot find module
```
*Solution:* Run `go mod tidy` to download dependencies

**Build fails:**
*Solution:* Ensure you have a clean Go environment:
```bash
go mod tidy
go clean -cache
make build
```

### Getting help

If you encounter issues during installation:

1. Check the [GitHub Issues](https://github.com/specmon/specmon/issues) for known problems
2. Ensure all prerequisites are properly installed
3. Try building with verbose output: `go build -v .`
4. For development setup issues, verify your Go environment: `go env`

## Next steps

Once SpecMon is installed, continue with:

- [**Quick Start**](/getting-started/quick-start/) — Create and run your first monitor
- [**Specification Basics**](/specifications/basics/) — Learn the specification language

## Contributing

Interested in contributing to SpecMon? See the [Contributing Guidelines](https://github.com/specmon/specmon/blob/main/CONTRIBUTING.md) on GitHub.
