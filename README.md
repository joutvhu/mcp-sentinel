# 🛡️ MCP Sentinel

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-65%2F65%20passing-brightgreen.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation)
[![Security](https://img.shields.io/badge/security-Zero--Trust%20%7C%20HMAC--SHA256-orange.svg)](#security-guarantees)

**mcp-sentinel** is a lightweight, high-performance **Zero-Trust Secret Vault & Security Isolation Proxy** built in Rust
for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers.

It prevents API keys, database credentials, and personal access tokens from being stored in plaintext configuration
files (`claude_desktop_config.json`, `mcp.json`), blocks malicious MCP servers from exfiltrating host environment
variables, enforces an interactive **Trust-On-First-Use (TOFU)** authorization model, and actively masks injected
secrets on `stdout` with **Data Loss Prevention (DLP)** streaming filters.

---

## 🛑 The Problem: The Hidden Security Gap in MCP

The Model Context Protocol (MCP) enables LLMs (such as Claude Desktop, Cursor, Continue, Windsurf) to execute local
commands and access external tools. However, the standard deployment model introduces severe security vulnerabilities:

```
❌ CONVENTIONAL MCP ARCHITECTURE (DANGEROUS):

  +---------------------+
  |   Claude / Cursor   |
  +----------+----------+
             |
             | Reads plaintext tokens from claude_desktop_config.json
             v
  +-----------------------------------------------------------+
  |                   Local MCP Child Process                 |
  |                                                           |
  |  1. Plaintext secrets visible in process list & disk      |
  |  2. Inherits ALL host env vars:                           |
  |     - AWS_SECRET_ACCESS_KEY                               |
  |     - GITHUB_TOKEN / SSH_AUTH_SOCK                        |
  |     - DB_PASSWORD / OPENAI_API_KEY                        |
  |  3. Any compromised npm/python package can exfiltrate all |
  |     host credentials back to an attacker's server!        |
  |  4. Injected secrets echoed to stdout leak into LLM chats |
  +-----------------------------------------------------------+
```

1. **Plaintext Secrets on Disk**: Credentials are saved as cleartext in user-accessible JSON files. These are frequently
   leaked via accidental git commits, backups, or malicious software scanning local directories.
2. **Ambient Environment Exfiltration**: Child processes spawned by your IDE inherit your complete shell environment
   (`std::env::vars()`). Any malicious or compromised dependency inside an MCP package can silently harvest your cloud
   keys, SSH agent sockets, and personal tokens.
3. **Zero Consent / Unrestricted Access**: Standard MCP hosts execute commands without prompting the user about what
   secrets an MCP server is requesting.
4. **Data Leakage via Stdout**: Even when secrets are securely injected into child processes, buggy or rogue MCP tools
   can print tokens directly to stdout, exposing credentials inside LLM conversation logs or cloud AI model prompts.
5. **Orphan / Zombie Processes**: Crashing or improperly closed MCP hosts frequently leave child node/python background
   processes running indefinitely, holding database connections and consuming system resources.

---

## 🛡️ The Solution: Zero-Trust Defense in Depth

`mcp-sentinel` acts as an intermediary transparent security proxy between the AI Host application and the actual MCP
server:

```
✅ ZERO-TRUST MCP-SENTINEL ARCHITECTURE:

  +---------------------+
  |   Claude / Cursor   |
  +----------+----------+
             | (Stdio JSON-RPC)
             v
  +----------------------------------------------------------------+
  |                         mcp-sentinel                           |
  |                                                                |
  |  [1] Resolves secrets directly from Native OS Keyring          |
  |      (Windows Credential Manager / Apple Keychain / SecretSvc) |
  |  [2] Verifies HMAC-SHA256 signature on permissions policy      |
  |  [3] Prompts Native OS Consent Dialog on first run (TOFU)      |
  |  [4] Wipes host environment (drops AWS, SSH, GITHUB keys)      |
  |  [5] Injects ONLY explicitly authorized secrets                |
  |  [6] Attaches to OS Job Object (guarantees orphan cleanup)     |
  |  [7] Stream DLP: Real-time secret masking on child stdout      |
  +------------------------------+---------------------------------+
                                 | (Sanitized Stdio Stream)
                                 v
                  +------------------------------+
                  |    Isolated Child Process    |
                  |  (npx / python / binary MCP) |
                  +------------------------------+
```

| Security Feature                  | Conventional MCP              | With `mcp-sentinel`                               |
| :-------------------------------- | :---------------------------- | :------------------------------------------------ |
| **Credential Storage**            | Plaintext in `.json` files    | Hardware/OS-backed Secure Keyring                 |
| **Host Environment**              | 100% exposed to child process | Stripped clean (Default-Deny Whitelist)           |
| **User Authorization**            | Silent automatic execution    | Native OS Pop-up Dialog (TOFU)                    |
| **Policy Integrity**              | None (editable by any script) | HMAC-SHA256 cryptographic signature               |
| **Data Loss Prevention (DLP)**    | Secrets echoed to stdout leak | Byte-level streaming masking across chunk borders |
| **Orphan Process Cleanup**        | Zombie processes linger       | Automatic tree termination (Job Object / Signals) |
| **Protocol Overhead**             | Baseline                      | **Zero perceptible latency** (~26,000 msgs/sec)   |

---

## 🚀 Installation

Pre-built binaries are available for Windows, macOS (Apple Silicon & Intel), and Linux with **no prerequisites
required**.

### 1. One-Line Quick Install

- **Windows (PowerShell):**

  ```powershell
  irm https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.ps1 | iex
  ```

- **macOS & Linux:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh
  ```

### 2. Package Managers

- **macOS / Linux (Homebrew):**

  ```bash
  brew install joutvhu/tap/mcp-sentinel
  ```

- **Windows (WinGet):**

  ```powershell
  winget install joutvhu.mcp-sentinel
  ```

- **Rust / Cargo:**
  ```bash
  cargo install mcp-sentinel
  ```

### 3. Upgrading

To upgrade to the latest version, simply re-run the one-line install command or use your package manager:

```bash
brew upgrade mcp-sentinel             # Homebrew
winget upgrade joutvhu.mcp-sentinel   # WinGet
cargo install --force mcp-sentinel    # Cargo
```

---

## ⚡ Quickstart (3 Easy Steps)

### Step 1: Save your secret in the OS Vault

Save your secret securely into your operating system's native credential store:

```bash
mcp-sentinel secrets set GITHUB_TOKEN ghp_xxxxxxxxxxxxxxxxxxxx
mcp-sentinel secrets set POSTGRES_PASSWORD mySuperSecretPassword123
```

### Step 2: Configure your AI Application

Replace the direct execution command in your host config with `mcp-sentinel run`.

#### Claude Desktop (`claude_desktop_config.json`)

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-sentinel",
      "args": [
        "run",
        "--name",
        "GitHub MCP Server",
        "--secrets",
        "GITHUB_TOKEN",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    },
    "postgres": {
      "command": "mcp-sentinel",
      "args": [
        "run",
        "--name",
        "Database MCP",
        "--secrets",
        "POSTGRES_PASSWORD",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://postgres@localhost/mydb"
      ]
    }
  }
}
```

#### Cursor (`mcp.json`)

- **Project Root**: `.cursor/mcp.json` or Global Cursor Settings

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-sentinel",
      "args": [
        "run",
        "--secrets",
        "GITHUB_TOKEN",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

### Step 3: Approve Consent Once (TOFU)

Upon first launch, `mcp-sentinel` detects a new command fingerprint and displays a native security prompt:

```
+--------------------------------------------------------------+
| MCP Sentinel Security Consent                                |
+--------------------------------------------------------------+
| The following MCP Server is requesting access to secrets:    |
|                                                              |
| Name: GitHub MCP Server                                      |
| Command: npx -y @modelcontextprotocol/server-github          |
| Requested Secrets: [GITHUB_TOKEN]                            |
|                                                              |
| Do you want to authorize this MCP server?                    |
| [Yes]                                                   [No] |
+--------------------------------------------------------------+
```

Once granted, your decision is remembered. Subsequent runs execute instantly with zero interruptions.

---

## 💻 CLI Command Reference

### `mcp-sentinel run`

Proxy an MCP server with environment isolation and secret injection.

```bash
mcp-sentinel run [OPTIONS] -- <COMMAND> [ARGS]...
```

- `--secrets <SPEC1,SPEC2,...>`: Comma-separated list of required secrets or alias mappings.
  - **Plain secret**: `GITHUB_TOKEN` (retrieves `GITHUB_TOKEN` from vault and injects as `GITHUB_TOKEN`).
  - **Aliased secret**: `TARGET_ENV=VAULT_KEY` (e.g., `API_KEY=OPENAI_PROD_KEY` retrieves `OPENAI_PROD_KEY` from vault and injects into child environment as `API_KEY`).
  - Allows multiple MCP servers using identical generic environment variable names (such as `API_KEY` or `DATABASE_URL`) to map cleanly to distinct secrets stored in your vault.
- `--no-redact`: Disable automatic Data Loss Prevention (DLP) secret masking on stdout. By default, Sentinel transparently redacts any authorized secrets echoed by the child process into `[REDACTED_BY_SENTINEL]`.
- `--name <NAME>`: Friendly display name shown in authorization prompts.
- `-- <COMMAND>`: Command and arguments of the target MCP server.

### `mcp-sentinel secrets` (alias: `secret`)

Manage secrets stored in native OS Credential Vault.

```bash
# Store or update a secret
mcp-sentinel secrets set <KEY> <VALUE>

# Retrieve a secret value
mcp-sentinel secrets get <KEY>

# Delete a secret
mcp-sentinel secrets delete <KEY>

# List all stored secret keys
mcp-sentinel secrets list
```

### `mcp-sentinel permissions` (alias: `permission`, `perm`)

Inspect and audit Trust-On-First-Use grants.

```bash
# List all active authorizations and command fingerprints
mcp-sentinel permissions list

# Revoke authorization for a specific fingerprint
mcp-sentinel permissions revoke <FINGERPRINT_HEX>

# Reset and purge all stored permissions
mcp-sentinel permissions reset
```

### `mcp-sentinel migrate`

Automatically scan and migrate existing plaintext MCP configuration files (`claude_desktop_config.json`, `mcp.json`) to Zero-Trust architecture. Extracts secrets into the OS Keyring, removes plaintext credentials from disk, and wraps commands with `mcp-sentinel`.

```bash
# Auto-detect and migrate all Claude and Cursor MCP configurations
mcp-sentinel migrate

# Target a specific application
mcp-sentinel migrate claude
mcp-sentinel migrate cursor

# Migrate a custom configuration file
mcp-sentinel migrate --file /path/to/claude_desktop_config.json

# Preview migration without modifying files or OS vault
mcp-sentinel migrate --dry-run
```

- Automatically generates a `.bak` backup file before overwriting.
- Safely resolves naming collisions by automatically generating isolated secret aliases.
- Skips servers that are already protected by `mcp-sentinel`.

### `mcp-sentinel ui` (alias: `tui`, `dashboard`)

Launch the interactive Terminal User Interface (TUI) Dashboard for visual secret and permission management.

```bash
mcp-sentinel ui
```

* **Keyboard Navigation & Shortcuts:**
  * `[↑]` / `[↓]`: Navigate menu items in the Sidebar, or items in the Content view
  * `[Enter]`: Select menu item, reveal secret, or trigger action
  * `[→]` / `[Tab]`: Enter content view from sidebar
  * `[←]` / `[Esc]`: Return focus to sidebar menu
  * `[1]` / `[2]` / `[3]`: Quick jump to Secrets Vault, Permissions, or System Status
  * `[a]`: Add new secret to OS Keyring
  * `[v]`: Reveal selected secret value in modal dialog
  * `[e]`: Edit / update selected secret value
  * `[d]` / `[Delete]`: Delete secret or revoke permission
  * `[r]`: Reload from OS Vault
  * `[x]`: Reset all permissions
  * `[q]`: Quit dashboard

---

## 🔒 Security Guarantees & Verification

`mcp-sentinel` is engineered under strict zero-trust principles:

1. **Deterministic Command Fingerprinting**: Policies are bound to `SHA256(canonical_command_args + requested_secrets)`.
   Modifying any argument (e.g., attempting command smuggling or adding extra flags) changes the hash and immediately
   triggers a new approval dialog.
2. **HMAC-SHA256 Anti-Tamper Signature**: The permission database (`permissions.json`) is cryptographically signed using
   a machine-bound master secret generated and locked inside your OS Keyring. If a rogue local process attempts to
   silently append permissions to `permissions.json`, `mcp-sentinel` detects signature mismatch, invalidates the file,
   and rejects execution.
3. **Strict Stderr Isolation**: The JSON-RPC protocol mandates clean standard streams. `mcp-sentinel` writes 100% of
   proxy logs, diagnostics, and notifications exclusively to `stderr`, guaranteeing zero protocol corruption on
   `stdout`.
4. **Child Process Anti-Recursion Lock**: Child processes running inside the MCP sandbox cannot access secrets or recursively invoke `mcp-sentinel`. The current executable path is also stripped from `PATH`.
5. **Real-Time Data Loss Prevention (DLP)**: Stream redactor powered by `aho-corasick` scans the child's `stdout` pipeline on the fly. Any injected secret value (≥ 5 characters) echoed back by rogue tools, error logs, or LLM output is masked with `[REDACTED_BY_SENTINEL]` before reaching the host IDE, cleanly handling split secrets across 8KB streaming chunk boundaries.
6. **UI Spoofing Defense**: The native authorization dialog collapses newlines and limits text lengths to prevent line-breaking and visual truncation attacks.
7. **Hardware-Backed CSPRNG**: The master signing key is generated via native OS entropy (`rand::rngs::OsRng`), ensuring cryptographic unpredictability.
8. **Verified by 65 Automated Tests across 5 Suites**:
   - **Unit Tests (34 tests)**: Vault operations, alias mapping & validation, fingerprint collision resistance, HMAC signing & tamper rejection, environment sanitizer whitelist, dialog text sanitization, interactive TUI input field navigation, and stream-boundary DLP redaction.
   - **Integration Tests (8 tests)**: Subprocess execution, CLI parsing, exit code propagation, secret list, permissions list, TUI launch commands, and full migration workflow.
   - **Security Penetration Tests (13 tests)**: Host environment variable exfiltration blocked, command injection (`;&|`) neutralized, forged permission injection rejected, argument smuggling intercepted, child process sandbox recursion blocked, reserved key name rejection, alias tamper resistance, and stdout DLP secret masking.
   - **Stress Tests (6 tests)**: 100-secret bulk injection, corrupted policy resilience, Unicode & Vietnamese character preservation, stdio separation.
   - **Performance Benchmarks (4 tests)**: High-load async stdio streaming (~26,000 JSON-RPC msgs/sec), multithreaded SHA-256 hashing (~320,000 ops/sec).

---

## 🛠️ Performance Metrics

Because `mcp-sentinel` is built in Rust using asynchronous zero-copy IO streams (`tokio`), overhead is virtually
undetectable:

- **Startup Overhead**: `< 2.5 ms`
- **Stdio Message Throughput**: `~26,000 messages / second`
- **Memory Footprint**: `~4.5 MB RSS`
- **Binary Size**: `~2.4 MB` (fully standalone, zero runtime dependencies)

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Where are my secrets physically stored?</b></summary>
Secrets are stored in your operating system's native secure enclave:
<ul>
  <li><b>Windows</b>: Windows Credential Manager under the target prefix <code>mcp-sentinel:secret:&lt;KEY&gt;</code>.</li>
  <li><b>macOS</b>: macOS Keychain under service <code>mcp-sentinel</code>.</li>
  <li><b>Linux</b>: Freedesktop Secret Service API (GNOME Keyring, KWallet) via DBus.</li>
</ul>
No plaintext secrets are ever written to disk or configuration files.
</details>

<details>
<summary><b>What happens if an MCP server tries to execute <code>process.env</code>?</b></summary>
The child process will only see a minimal baseline environment required for execution (e.g., <code>PATH</code>, <code>SYSTEMROOT</code>, <code>TEMP</code>) plus the specific secrets you explicitly authorized via <code>--secrets</code>. All other host variables (such as <code>AWS_SECRET_ACCESS_KEY</code>, <code>SSH_AUTH_SOCK</code>, <code>GITHUB_PAT</code>) are completely invisible.
</details>

<details>
<summary><b>Can an unauthorized script modify <code>permissions.json</code> to bypass the dialog?</b></summary>
No. <code>permissions.json</code> is guarded by an <b>HMAC-SHA256 signature</b> computed with a master key stored in the OS Keyring. If the file is altered without a valid HMAC signature, <code>mcp-sentinel</code> refuses to load it, discards the tampered file, and requires manual user confirmation.
</details>

<details>
<summary><b>Does mcp-sentinel slow down my AI interactions?</b></summary>
No. Once authorized, <code>mcp-sentinel</code> acts as an ultra-fast asynchronous duplex stream proxy. It forwards raw bytes between <code>stdin</code> and <code>stdout</code> at over 26,000 messages per second with microsecond latency.
</details>

<details>
<summary><b>Can a compromised MCP server invoke <code>mcp-sentinel</code> to steal other secrets?</b></summary>
No. <code>mcp-sentinel</code> enforces a strict two-layer anti-recursion defense:
<ol>
  <li>The directory containing the <code>mcp-sentinel</code> binary is automatically filtered out of the child process's <code>PATH</code>.</li>
  <li>A security canary flag (<code>MCP_SENTINEL_CHILD_CONTEXT=1</code>) is locked into the child environment. Any recursive invocation of <code>mcp-sentinel</code> from within the sandbox immediately terminates with exit code <code>13</code> (Permission Denied).</li>
</ol>
</details>

<details>
<summary><b>How do I revoke a previously granted permission?</b></summary>
Run <code>mcp-sentinel permissions list</code> to view all active grants and their fingerprint IDs. To revoke a single grant, run <code>mcp-sentinel permissions revoke &lt;FINGERPRINT_HEX&gt;</code>. To wipe all grants and force fresh prompts for every server, run <code>mcp-sentinel permissions reset</code>.
</details>

<details>
<summary><b>Does mcp-sentinel require Administrator or Root privileges?</b></summary>
No. <code>mcp-sentinel</code> runs entirely in user-space, storing credentials inside your personal OS user vault (Windows Credential Manager, macOS Keychain, or Linux Secret Service). It strictly adheres to the principle of least privilege and does not require elevated rights.
</details>

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
