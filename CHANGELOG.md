# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-17

### 🚀 Initial Stable Production Release

This marks the first official major release of **MCP Sentinel**, a zero-trust secret vault and security proxy designed specifically for the Model Context Protocol (MCP).

### ✨ Features & Capabilities

- **Zero-Trust Transparent Stdio Proxy:**
  - Full bidirectional transparent streaming of `stdin`, `stdout`, and `stderr`.
  - Guarantees 100% protocol fidelity for JSON-RPC without interfering with LLM communication.
  - Diagnostic logs strictly separated and isolated to `stderr`.

- **Native OS Keyring Vault:**
  - Secure credential storage backed by Windows Credential Manager, macOS Keychain, and Linux Secret Service (D-Bus / FreeDesktop Secret Service).
  - Deterministic HMAC-SHA256 master key derivation with protected fallback (`0600` permissions) for headless / CI / containerized environments.
  - Safe key name validation conforming to strict environment variable naming rules.

- **Trust-On-First-Use (TOFU) Consent Model:**
  - Interactive native OS authorization dialog (`rfd`) prompting user approval when an MCP server requests new secrets.
  - SHA-256 fingerprinting based on executable path and arguments with null-byte separators to prevent delimiter smuggling.
  - HMAC-SHA256 policy file tampering detection; invalid or modified grants are rejected automatically.

- **Subprocess Environment Isolation & Sandboxing:**
  - Whitelist-only environment variable policy; completely strips host secrets (`AWS_SECRET_ACCESS_KEY`, `SSH_AUTH_SOCK`, `GITHUB_TOKEN`).
  - Anti-recursion security guard: child MCP processes cannot invoke `mcp-sentinel` (`MCP_SENTINEL_CHILD_CONTEXT=1`).
  - Automatic `PATH` filtering removes the directory containing the sentinel binary.
  - Windows Job Objects binding to guarantee immediate termination of child process trees when the host closes.

- **Interactive TUI Dashboard (`mcp-sentinel ui`):**
  - Full terminal dashboard powered by `ratatui` and `crossterm`.
  - Real-time management of vault secrets (Add, Edit, View, Delete) and TOFU grants (Inspect, Revoke, Reset).
  - Interactive text input field with cursor navigation (`Left`, `Right`, `Home`, `End`), inline editing (`Backspace`, `Delete`), and horizontal scrolling for long secrets.
  - Safety-first confirmation modals: destructive actions strictly require the `y` key (accidental `Enter` presses are disabled).

- **Multi-Platform Automated Distribution:**
  - Precompiled binaries for Windows (`x86_64`), macOS (`x86_64` & `aarch64`), and Linux (`x86_64`).
  - One-line quick installer scripts for Unix (`install.sh`) and Windows (`install.ps1`).
  - Automated publishing pipelines for Crates.io, Homebrew Tap, and Windows WinGet.

### 🛡️ Test Coverage & Quality
- **44/44 automated tests passing** across Unit, Integration, Stress, Performance Benchmark, and Penetration/Security Hacking suites.
- Fully verified and passing across Windows, Ubuntu, and macOS in continuous integration.
