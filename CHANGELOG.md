# Changelog

## [1.1.0] - 2026-10-21

### 🚀 Major Feature Release: L7 Tool Call Firewall, Config Migration & DLP

This release introduces comprehensive Layer 7 tool call interception, automated client configuration migration across 11 AI agents/IDEs, non-secret environment passthrough (`--pass-env`), real-time data loss prevention (DLP), fast-path zero-copy stream forwarding, opt-in security audit logging, and a modular high-performance TUI with dual-build release options.

### ✨ New Features & Capabilities

- **Automated Multi-Agent Configuration Migration (`mcp-sentinel migrate`):**
  - One-click discovery and migration across 11 major AI Agents and IDEs: **Claude Desktop**, **Claude Code**, **Cursor**, **Antigravity**, **Kiro**, **Codex**, **Windsurf**, **Cline**, **Roo Code**, **VS Code**, and **Continue**.
  - Dedicated CLI sub-targets (e.g., `mcp-sentinel migrate antigravity`, `mcp-sentinel migrate kiro`, `mcp-sentinel migrate codex`) or universal scan (`mcp-sentinel migrate`).
  - Safely extracts credentials directly into the OS-backed hardware keyring and rewrites server configs to invoke `mcp-sentinel run`.
  - Supports `--dry-run` inspection and automatic `.bak` backup creation.
  - **Intelligent Non-Secret Variable Separation**: Automatically detects non-secret configuration variables, preserving them via `--pass-env` flags to prevent DLP over-redaction.
  - **JSONC Support**: Full support for JSON with comments (`//`, `/* */`) and trailing commas in configuration files.
  - **Environment Variable Placeholder Resolution**: Expands `${env:VAR}`, `${VAR}`, and `$VAR` from the host environment to migrate live secrets securely into the vault.

- **Non-Secret Environment Passthrough (`--pass-env` / `--env`):**
  - Safely passes through non-secret host environment variables (e.g., `DEBUG`, `LANG`, `CUSTOM_CONFIG`) while maintaining a default-deny zero-trust security posture.
  - **Runtime Injection Shield**: Automatically blocks dangerous execution controls (e.g., `NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), even when explicitly requested in `--pass-env`.

- **Layer 7 Tool Call Firewall & Security Policies (`mcp-sentinel tool-policy`):**
  - In-stream inspection of JSON-RPC `tools/call` invocations on `stdin`.
  - Reusable security profiles with whitelist (`allow`) and priority blacklist (`deny`) pattern matching.
  - Built-in presets:
    - `read-only`: Whitelists read/query/list/get operations; strictly drops mutating or executing tool calls.
    - `no-destructive`: Allows general execution while blacklisting high-risk tools matching `*delete*`, `*drop*`, `*remove*`, `*destroy*`, `*terminate*`.
  - JSON-RPC specification compliant: dropped calls return standard JSON-RPC error `-32001` (Tool Execution Denied) without terminating the server.
  - Support for custom profiles via `mcp-sentinel profile set <NAME> --allow <PATS> --deny <PATS>`.

- **Fast-Path Zero-Copy Proxy Forwarding:**
  - Forward allowed tool calls byte-for-byte without re-serialization overhead, preserving original formatting and 64-bit integer precision.
  - Mixed batch handling: seamlessly synthesizes error responses for blocked calls while allowing authorized tool calls in the same batch to execute with zero-copy forwarding.

- **Data Loss Prevention (DLP) & Stream-Level Secret Redaction:**
  - Real-time scanning and masking of secrets leaking onto `stdout` using high-throughput Aho-Corasick matching.
  - Suffix-prefix boundary buffer guarantees detection even when a secret is fragmented across TCP/pipe chunk borders.
  - JSON-escaped secret detection (handles `\"`, `\\`, `\uXXXX`).
  - Safe-word exclusion dictionary preventing false-positive redaction of common literals (`false`, `true`, `null`, `production`, etc.).
  - Can be bypassed via `--no-redact` when verbatim stream transmission is explicitly required.

- **Ephemeral "Allow Once" Consent:**
  - Native TOFU dialog now offers three choices: `[Allow Always]`, `[Allow Once]`, and `[Deny]`.
  - "Allow Once" grants in-memory access for the current session only without persisting authorization to `permissions.json`.
  - CLI flag `--allow-once` (alias `--once`) enforces ephemeral permissions even for pre-authorized servers.

- **Security Audit Logging (`mcp-sentinel audit`):**
  - Opt-in cryptographic security audit trail recorded to `~/.mcp-sentinel/audit.log`.
  - Tracks all credential accesses, user TOFU decisions, L7 tool firewall drops, and migration events.
  - Default-off for zero disk footprint; easily managed via `audit list`, `audit clear`, and `audit status`.

- **Flexible Secret Aliasing:**
  - Support for environment variable mapping syntax: `--secrets TARGET_VAR=VAULT_KEY`.
  - Allows multiple servers to share a single vault secret under differing environment variable names without duplicating secrets.

- **Modular TUI Dashboard & Enhanced UX (`mcp-sentinel ui`):**
  - Refactored monolithic TUI into clean, maintainable submodules under `src/tui/`.
  - Three-column intuitive navigation (`Sidebar` -> `Content` -> `Detail Pane`).
  - Native mouse wheel and trackpad scrolling across all panels and popups.
  - Full-detail modal view (`Enter` or `v`) for inspecting extensive tool policies and grant specifications on small terminals.
  - Responsive layout dynamically auto-hiding header banners on compact screens (<12 rows).

- **Dual-Build Packaging (Standard & Headless Editions):**
  - Added optional `tui` Cargo feature flag: `--no-default-features` builds a micro-binary without GUI/TUI dependencies.
  - Automated dual-release GitHub Actions CI/CD publishing both `mcp-sentinel` (Full with TUI) and `mcp-sentinel-headless` (Micro-binary).
  - One-line install scripts (`install.ps1`, `install.sh`) now support `-Headless` / `--headless`.

- **Process Lifecycle Termination (`mcp-sentinel kill` / `stop`):**
  - Added dedicated CLI command to discover and terminate all background proxy instances before upgrades, eliminating Windows executable file locks (`Access is denied (os error 5)`).
  - Integrated pre-upgrade automatic process stopping into `install.ps1` and `install.sh`.

### 🛡️ Security Hardening & Bug Fixes

- **JSON-RPC Batch Request Firewall**: Extended L7 firewall to recursively parse and validate JSON-RPC batch arrays, ensuring destructive calls cannot bypass policies via batch smuggling.
- **Headless Pre-Authorization CLI (`mcp-sentinel permissions grant`)**: Added command to pre-authorize MCP servers on headless or remote SSH servers without requiring interactive prompts.
- **Strict Hardware/OS Keyring Storage**: Master encryption key now stays exclusively in OS Keyring; disk fallback file `.master_key` is completely disabled unless explicitly requested via `MCP_SENTINEL_ALLOW_INSECURE_KEYFILE=1`.
- **DLP Safe Word Protection**: Excluded common programming and configuration literals (`false`, `true`, `null`, `production`, etc.) from redactor dictionary, preventing corruption of valid JSON RPC responses.
- **Subprocess Tree Teardown on Unix & Windows**: Configured process groups with automatic `SIGTERM` signal propagation on Unix and Windows Job Objects to eliminate orphan background and grandchild processes.
- **Grandchild Pipe Hang Defense**: Resolved stdout/stderr pipe deadlocks when spawned grandchild processes inherit standard descriptors.
- **System Tool & Path Safety**: Eliminated recursive directory stripping from `PATH` and included standard Linux variables (`XDG_*`, `SSL_CERT_*`, `VIRTUAL_ENV`) in whitelist.
- **Case-Preserving Config Migration**: Preserved camelCase env keys and added leading underscore sanitization for numeric names during `mcp-sentinel migrate`.
- **Multi-Line & Pretty-Printed JSON-RPC Firewall**: Replaced line-by-line reading with streaming deserialization, preventing bypass of L7 firewall via multi-line JSON-RPC payloads (SEC-01).
- **Stdin Buffer DoS Protection**: Bounded stdin buffer to 64KB (configurable via `MCP_SENTINEL_MAX_STDIN_BUFFER_BYTES`) to prevent slow-drip memory exhaustion attacks.
- **Expanded Stdout Safety Buffer**: Increased proxy stdout buffer to 2MB to support large legitimate MCP payloads without pipe stalling.
- **Strict HMAC Validation**: Denied untrusted/tampered tool policy profiles without fallback auto-signing when signatures are absent or invalid (SEC-02).
- **Master Key Name Protection**: Blocked retrieval or deletion of internal `__master_key__` via CLI secret management commands (SEC-04).
- **Atomic Line Interleaving**: Guarded child stdout chunk line-buffering to prevent synthetic error frames from corrupting child JSON-RPC responses (BUG-01).
- **Headless Master Key Persistence**: Fixed master key reload from file in containerized/headless environments when OS keyring is unavailable (BUG-02).
- **Migrate Prefix Collision Guard**: Automatically prefixed reserved server keys (`MCP_SENTINEL*`) with `SRV_` to avoid migration failures (BUG-03).
- **Unicode Homoglyph & Trojan Source Defense**: Added deconfusing for Cyrillic, Greek, and full-width Latin homoglyphs in L7 tool firewall, and immediately fail-closed on zero-width spaces and bidi override controls to stop blacklist evasions (SEC-05).
- **Profile Binding in TOFU Grants**: Binds the active tool policy profile directly into the cryptographic fingerprint to force re-authorization if policies change.
- **Atomic Vault Registry Persistence**: Ensured `.vault_keys.json` writes use PID-tagged temporary files and atomic rename with 0600 permissions to prevent file corruption under concurrent operations.
- **Proxy Lifecycle & Memory Safeguards**: Prevented background stdin worker leak when child terminates, safeguarded stdout buffer against unbounded memory growth, and resolved stdout writer busy-loop when synthetic error channel closes.

### 🛡️ Test Coverage & Quality
- **135/135 automated tests passing** across 7 test suites: Unit (77), Security Hacking (31), Integration (9), Concurrency (5), Fast-Path (3), Stress (6), and Performance Benchmarks (4).
- 0 compiler warnings, 0 clippy warnings, 100% rustfmt compliant.

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
