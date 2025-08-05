# SpecMon

<p align="center">
  <img src="logo.png" alt="SpecMon Logo" width="150">
</p>

<p align="center">
  <b>Runtime monitoring of formal specifications</b>
</p>

<p align="center">
  <a href="https://github.com/specmon/specmon/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/specmon/specmon/go.yml?branch=main" alt="Build Status">
  </a>
  <a href="https://github.com/specmon/specmon/issues">
    <img src="https://img.shields.io/github/issues/specmon/specmon" alt="Issues">
  </a>
  <a href="https://github.com/specmon/specmon/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/specmon/specmon" alt="License">
  </a>
</p>

---

## 🎯 About

SpecMon ensures that real-world systems comply with their formal specifications by monitoring applications at runtime. It tracks application behavior through event streams and verifies compliance with the defined rules. SpecMon is lightweight, capable of handling complex scenarios, and supports multiple concurrent sessions.

---

## ✨ Features

- **Flexible Architecture**: Choose your preferred event aggregation method.
- **Multi-Session Monitoring**: Seamlessly handle multiple concurrent sessions.
- **Debugging Made Easy**: Quickly identify and fix errors with clear debug output.

---

## 📦 Installation

### Prerequisites

- [Go 1.21.4+](https://go.dev/)
- [Git](https://git-scm.com/)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/specmon/specmon.git
   ```

2. Navigate to the project directory:
   ```bash
   cd specmon
   ```

3. Build the application:
   ```bash
   go build
   ```

---

## 🚀 Usage

*Note: Detailed documentation and examples will be linked here soon.*


   ```bash
$ ./specmon --help
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

Use "specmon [command] --help" for more information about a command.
   ```
---

## 🤝 Contributing

Any contributions you make are **greatly appreciated**.

For details on how to get started, please see our [Contributing Guidelines](.github/CONTRIBUTING.md).

---

## 📜 License

This project is licensed under the GNU Affero General Public License (AGPL) 3.0. See the [LICENSE](LICENSE) file for details.

---

## 📚 Citation

If you use SpecMon in your research or projects, please cite it as follows:

```text
@inproceedings{morio2024specmon,
  title={SpecMon: Modular Black-Box Runtime Monitoring of Security Protocols},
  author={Morio, Kevin and K{\"u}nnemann, Robert},
  booktitle={Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security},
  pages={2741--2755},
  year={2024}
}
```

