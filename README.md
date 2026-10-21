# 🛡️ MCP Sentinel

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-135%2F135%20passing-brightgreen.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation)
[![Security](https://img.shields.io/badge/security-Zero--Trust%20%7C%20HMAC--SHA256-orange.svg)](#security-guarantees)

**mcp-sentinel** is a lightweight, high-performance **Zero-Trust Secret Vault & Security Isolation Proxy** built in Rust
for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers.

It prevents API keys, database credentials, and personal access tokens from being stored in plaintext configuration
files (`claude_desktop_config.json`, `mcp.json`), blocks malicious MCP servers from exfiltrating host environment
variables, enforces an interactive **Trust-On-First-Use (TOFU)** authorization model, inspects and controls tool calls
with an in-stream **Layer 7 Tool Firewall (Whitelist/Blacklist & Reusable Profiles)**, and actively masks injected
secrets on `stdout` with **Data Loss Prevention (DLP)** streaming filters.

---

## 🛑 The Problem: The Hidden Security Gap in MCP

The Model Context Protocol (MCP) enables LLMs (such as Claude Desktop, Cursor, Continue, Windsurf) to execute local
commands and access external tools. However, the standard deployment model introduces severe security vulnerabilities:

```mermaid
flowchart TD
    Host["Claude Desktop / Cursor / AI Host"]
    ConfigFile[("📄 Plaintext Config<br/>claude_desktop_config.json / mcp.json")]
    Child["⚠️ Unprotected MCP Child Process<br/>(Node.js / Python / Binary)"]
    HostEnv[("💥 Full Host Environment<br/>AWS_SECRET_ACCESS_KEY<br/>GITHUB_TOKEN / SSH_AUTH_SOCK<br/>DB_PASSWORD / OPENAI_API_KEY")]
    Attacker["🚨 Malicious / Compromised Dependency<br/>(Exfiltrates Credentials to Remote Server)"]

    ConfigFile -.->|"1. Exposes plaintext credentials"| Host
    Host -->|"Spawns process with cleartext args"| Child
    HostEnv -->|"2. Ambient environment fully inherited"| Child
    Child -->|"3. Silently harvests & exfiltrates host keys"| Attacker
    Child -->|"4. Injected secrets echoed on stdout leak into LLM chats"| Host
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

```mermaid
flowchart TD
    Host["Claude / Cursor / IDE"]
    
    subgraph Sentinel["🛡️ mcp-sentinel (Zero-Trust Security Proxy)"]
        direction TB
        L7["[8] Layer 7 Tool Firewall<br/>(In-stream stdin inspection & -32001 drop)"]
        TOFU["[3] TOFU Native Consent Dialog<br/>(Prompt user on first execution)"]
        HMAC["[2] HMAC-SHA256 Policy Verifier<br/>(Cryptographic tamper detection)"]
        Vault["[1] Native OS Keyring Vault<br/>(Windows Credential Mgr / Keychain / Secret Service)"]
        Sanitizer["[4, 5] Environment Sanitizer<br/>(Default-Deny whitelist & pass-env validation)"]
        DLP["[7] Stream DLP Redactor<br/>(Real-time stdout secret masking)"]
        JobObj["[6] Process Supervisor<br/>(Windows Job Object / Unix Process Groups)"]
    end
    
    Child["Isolated Child Process<br/>(Node.js / Python / Binary MCP Server)"]

    Host -->|"JSON-RPC Request (stdin)"| L7
    L7 -->|"Authorized Commands"| Child
    Vault -.->|"Inject Authorized Secrets"| Sanitizer
    HMAC -.->|"Verify Policy"| Sanitizer
    TOFU -.->|"Grant Consent"| Sanitizer
    Sanitizer -->|"Sanitized Env & Secrets"| Child
    Child -->|"Raw Output (stdout)"| DLP
    DLP -->|"Safe Output (stdout)"| Host
    JobObj -.->|"Process Tree Teardown"| Child
```

| Security Feature                  | Conventional MCP              | With `mcp-sentinel`                               |
| :-------------------------------- | :---------------------------- | :------------------------------------------------ |
| **Credential Storage**            | Plaintext in `.json` files    | Hardware/OS-backed Secure Keyring                 |
| **Host Environment**              | 100% exposed to child process | Stripped clean (Default-Deny Whitelist)           |
| **User Authorization**            | Silent automatic execution    | Native OS Pop-up Dialog (TOFU)                    |
| **Policy Integrity**              | None (editable by any script) | HMAC-SHA256 cryptographic signature               |
| **Tool Call Firewall (L7)**       | Unrestricted tool execution   | In-stream JSON-RPC inspection & Profile Filtering |
| **Data Loss Prevention (DLP)**    | Secrets echoed to stdout leak | Byte-level streaming masking across chunk borders |
| **Orphan Process Cleanup**        | Zombie processes linger       | Automatic tree termination (Job Object / Signals) |
| **Protocol Overhead**             | Baseline                      | **Zero perceptible latency** (~46,000+ msgs/sec)  |

---

## 🚀 Installation

Pre-built binaries are available for Windows, macOS (Apple Silicon & Intel), and Linux with **no prerequisites
required**.

### 1. One-Line Quick Install

- **Windows (PowerShell):**

  ```powershell
  # Standard Edition (with TUI Dashboard - Default)
  irm https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.ps1 | iex

  # Headless Edition (Micro-binary without TUI, ideal for CI/CD & Docker)
  & { $(irm https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.ps1) } -Headless
  ```

- **macOS & Linux:**
  ```bash
  # Standard Edition (with TUI Dashboard - Default)
  curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh

  # Headless Edition (Micro-binary without TUI, ideal for CI/CD & Docker)
  curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh -s -- --headless
  ```

### 2. Package Managers & Cargo

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
  # Standard Edition
  cargo install mcp-sentinel

  # Headless Edition
  cargo install mcp-sentinel --no-default-features
  ```

### 3. Upgrading

To upgrade to the latest version, re-run the one-line install command (which automatically stops running background instances before replacing the binary) or use your package manager.

> 💡 **Tip for Windows & Cargo users**: If `mcp-sentinel` is currently active inside your IDEs (Claude Desktop, Cursor, etc.), run `mcp-sentinel kill` first to terminate background proxy workers and release executable file locks:

```bash
# Terminate background instances to prevent "Access is denied (os error 5)" on Windows
mcp-sentinel kill

# Upgrade via your preferred package manager
brew upgrade mcp-sentinel             # Homebrew (macOS / Linux)
winget upgrade joutvhu.mcp-sentinel   # WinGet (Windows)
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

#### Option A: Automatic Migration (Recommended)

If you already have existing MCP servers configured in any AI agent (Claude, Cursor, Antigravity, Kiro, Codex, Windsurf, Cline, Roo Code, etc.), Sentinel can automatically extract secrets into your OS vault, strip plaintext credentials from disk, and wrap server commands with a single command:

```bash
# Auto-detects and migrates ALL installed AI agents on your system
mcp-sentinel migrate
```

#### Option B: Manual Configuration

Alternatively, wrap your server commands directly in your agent's MCP configuration file using `mcp-sentinel run`:

##### Claude Desktop (`claude_desktop_config.json`)

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
        "--profile",
        "read-only",
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

##### Cursor (`mcp.json`), Antigravity, Kiro, or Codex

- **Cursor**: `.cursor/mcp.json` or `~/.cursor/mcp.json`
- **Antigravity**: `~/.gemini/config/mcp_config.json` or `.agents/mcp_config.json`
- **Kiro**: `~/.kiro/settings/mcp.json` or `.kiro/mcp.json`
- **Codex**: `~/.codex/mcp.json` or `.codex/mcp.json`

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

### Step 3: Authorize via Trust-On-First-Use (TOFU)

Upon first launch, `mcp-sentinel` detects a new command fingerprint and displays a native security prompt offering granular consent:

```
+--------------------------------------------------------------+
| MCP Sentinel Security Authorization                          |
+--------------------------------------------------------------+
| The following MCP Server is requesting access to secrets:    |
|                                                              |
| Name: GitHub MCP Server                                      |
| Command: npx -y @modelcontextprotocol/server-github          |
| Requested Secrets: [GITHUB_TOKEN]                            |
|                                                              |
| Do you authorize this MCP server to access these secrets?    |
| - [Allow Always]: Authorize and remember for future sessions |
| - [Allow Once]: Grant for this execution only (ephemeral)    |
| - [Deny]: Reject access and terminate                        |
|                                                              |
| [Allow Always]           [Allow Once]                 [Deny] |
+--------------------------------------------------------------+
```

- **Allow Always**: Saves the cryptographic grant to `permissions.json`. Subsequent runs execute instantly with zero interruptions.
- **Allow Once**: Authorizes the server for the current run only, keeping the grant in-memory. The next launch will prompt again.
- **Deny**: Immediately aborts execution and denies access to credentials.

---

## 🛡️ Layer 7 Tool Call Firewall & Security Profiles

When autonomous AI agents (Claude, Cursor, Cline, etc.) connect to MCP servers, they often possess capabilities to execute destructive tools — such as deleting production files, dropping database tables, wiping git branches, or making irreversible API calls. 

`mcp-sentinel` includes an in-stream **Layer 7 JSON-RPC Tool Firewall** that inspects tool requests on `stdin` before the child process ever sees them.

```mermaid
sequenceDiagram
    autonumber
    actor LLM as AI Host / LLM
    participant Proxy as mcp-sentinel (L7 Firewall)
    participant Child as Isolated Child Process (MCP)

    LLM->>Proxy: JSON-RPC tools/call ("drop_database")
    Note over Proxy: Inspect Tool Policy Profile (e.g., 'read-only')
    alt Tool matches Deny pattern or not Whitelisted
        Proxy-->>LLM: JSON-RPC Error -32001 (Execution Denied)
        Note over Proxy,Child: Request is DROPPED (Child never sees it)
    else Tool is Authorized
        Proxy->>Child: Fast-Path Forward (Raw JSON-RPC bytes)
        Child-->>Proxy: Tool Result (stdout)
        Note over Proxy: Real-time DLP Secret Masking
        Proxy-->>LLM: Sanitized Output
    end
```

### 1. Built-in Security Profiles

Sentinel provides pre-configured, production-ready security profiles out of the box:

| Profile Name | Default Action | Behavior & Rules |
| :--- | :--- | :--- |
| `read-only` | **Deny All Mutating Calls** | Whitelists read/query/list/get operations (`read_*`, `get_*`, `list_*`, `query_*`, `select_*`, etc.). Strictly blocks any mutating, writing, or executing tool calls. |
| `no-destructive` | **Permit Safe Operations** | Allows general development operations while blocking high-risk tools matching `*delete*`, `*drop*`, `*remove*`, `*destroy*`, `*terminate*`, `*truncate*`. |

To enforce a profile, simply add `--profile <NAME>`:
```bash
mcp-sentinel run --profile read-only --secrets DB_PASSWORD -- npx -y @modelcontextprotocol/server-postgres postgresql://...
```

### 2. Ad-Hoc Tool Filtering (`--allow-tools` & `--deny-tools`)

You can also specify inline tool restrictions directly in your server configuration without creating a profile:

```bash
# Block any delete or drop tools, allow everything else
mcp-sentinel run --deny-tools "*delete*,*drop*,*truncate*" -- node server.js

# Allow only specific query and inspect tools
mcp-sentinel run --allow-tools "query_*,inspect_*,get_*" -- python server.py
```
> ⚠️ **Rule Precedence**: Deny patterns (`--deny-tools`) strictly override allow patterns.

### 3. Custom Reusable Profiles

Create, customize, and manage reusable profiles signed with HMAC-SHA256:

```bash
# Create an analytics policy
mcp-sentinel profile set db-analyst \
  --allow "get_*,select_*,query_*,explain_*" \
  --deny "*drop*,*delete*,*truncate*,*alter*,*update*,*insert*" \
  --description "Read-only database analytics queries"

# View profile rules
mcp-sentinel profile get db-analyst
```

### 4. What Happens When a Tool is Blocked?
* **Zero Disruption to AI Chat**: Sentinel synthesizes a valid JSON-RPC error response (`code: -32001`, `message: "[MCP-SENTINEL] Tool 'xyz' is blocked by security policy 'read-only'"`). The AI model gracefully understands the action was denied and continues the conversation without crashing.
* **Child Process Unaffected**: The target child process never receives the blocked frame, ensuring no accidental side-effects or partial mutations occur.

---

## 🚫 How MCP Sentinel Blocks Dangerous Programs & Hijacks

Beyond secret protection and tool firewalling, `mcp-sentinel` enforces four distinct layers of **program execution blocking and sandboxing** to prevent malicious code execution:

```mermaid
flowchart TD
    subgraph L1["1. Unauthorized Program Execution Block (TOFU)"]
        A1["Unverified Command / Altered Arguments"] --> A2{"User Consent Dialog"}
        A2 -->|Deny| A3["Immediate Halt (Exit Code 1)"]
        A2 -->|Allow| A4["Proceed to Isolation Sandbox"]
    end

    subgraph L2["2. Anti-Recursion Security Lock"]
        B1["Child Process in Sandbox"] --> B2{"Attempt mcp-sentinel invocation?"}
        B2 -->|Yes| B3["Blocked by Canary & PATH Stripping (Exit Code 13)"]
        B2 -->|No| B4["Normal Tool Execution"]
    end

    subgraph L3["3. Dangerous Runtime Control Shield"]
        C1["Host Environment & --pass-env"] --> C2{"Check Dangerous Controls"}
        C2 -->|NODE_OPTIONS, LD_PRELOAD, etc.| C3["Strictly Stripped / Blocked"]
        C2 -->|Safe Non-Secret Variables| C4["Clean Environment Injected"]
    end

    subgraph L4["4. Zombie & Grandchild Process Cleanup"]
        D1["Host IDE Closes or Crashes"] --> D2["Windows Job Object / Unix SIGTERM"]
        D2 --> D3["All Child & Grandchild Processes Terminated"]
    end
```

1. **Unauthorized Program Blocking (TOFU Consent)**:
   - Untrusted MCP commands or altered arguments are blocked immediately on launch.
   - If the user selects `[Deny]` in the consent dialog, Sentinel immediately halts with exit code `1` without launching the child command or decrypting any secrets.
2. **Anti-Recursion Lock (Canary Defense)**:
   - Malicious MCP packages cannot spawn a subshell to run `mcp-sentinel secrets get` or elevate privileges.
   - Sentinel sets `MCP_SENTINEL_CHILD_CONTEXT=1` in the child environment and removes its own binary directory from `PATH`.
   - Any attempt to run `mcp-sentinel` inside the sandbox instantly terminates with exit code `13` (`Permission Denied`).
3. **Dangerous Runtime Hijack Defense**:
   - Attackers frequently exploit environment variables to force Node.js or Python to load malicious code before executing the main script (e.g. `NODE_OPTIONS=--require /tmp/evil.js` or `PYTHONPATH=/tmp/pwned`).
   - Sentinel blocks dangerous runtime control variables (`NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.), even if a user or config file mistakenly includes them in `--pass-env`.
4. **Zombie & Grandchild Process Termination**:
   - Standard MCP servers often leave orphaned background processes running when the IDE closes or crashes.
   - Sentinel attaches subprocesses to Windows Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) and Unix Process Groups (`SIGTERM`), ensuring all child and grandchild processes are cleanly killed.

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
- `--pass-env <VAR1,VAR2,...>` (alias `--env`): Comma-separated list of non-secret host environment variables to safely pass through to the child MCP server (e.g., `DEBUG,LANG,CONFIG_PATH`). Dangerous runtime control variables (`NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.) are automatically blocked to prevent execution hijacks.
- `--allow-once` (alias `--once`): Authorize this execution once without persisting permission to `permissions.json`.
- `--profile <NAME>`: Apply a pre-configured or custom tool policy profile (e.g., `read-only`, `no-destructive`).
- `--allow-tools <PATS>`: Comma-separated allowed tool patterns with wildcard support (e.g., `read_*,get_*,list_*`).
- `--deny-tools <PATS>`: Comma-separated denied tool patterns with wildcard support (e.g., `*drop*,*delete*,*destroy*`). Strictly overrides allow patterns.
- `--no-redact`: Disable automatic Data Loss Prevention (DLP) secret masking on stdout. By default, Sentinel transparently redacts any authorized secrets echoed by the child process into `[REDACTED_BY_SENTINEL]`.
- `--audit`: Enable structured security audit logging for this session. **Default is OFF (opt-in)** for zero disk footprint and maximum privacy. Can also be enabled via environment variable `MCP_SENTINEL_AUDIT=1` or `MCP_SENTINEL_AUDIT=true`.
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

# Pre-authorize an MCP server command without interactive prompts (ideal for headless servers, SSH, or CI/CD)
mcp-sentinel permissions grant [--name <NAME>] --secrets <SPEC1,SPEC2,...> [--profile <NAME>] -- <COMMAND> [ARGS]...

# Revoke authorization for a specific fingerprint
mcp-sentinel permissions revoke <FINGERPRINT_HEX>

# Reset and purge all stored permissions
mcp-sentinel permissions reset
```

### `mcp-sentinel profile` (alias: `profiles`, `tool-policy`)

Manage reusable Layer 7 Tool Policy Profiles for granular tool call whitelisting and blacklisting. Profiles are cryptographically signed with HMAC-SHA256 to prevent local tampering.

```bash
# List all configured profiles (includes built-in presets: read-only, no-destructive)
mcp-sentinel profile list

# View detailed specifications of a profile
mcp-sentinel profile get <NAME>

# Create or update a reusable profile
mcp-sentinel profile set <NAME> --allow <PATTERNS> --deny <PATTERNS> [--description <DESC>]

# Example: Create an analytics-only policy
mcp-sentinel profile set db-analyst \
  --allow "get_*,select_*,query_*,explain_*" \
  --deny "*drop*,*delete*,*truncate*,*alter*,*update*,*insert*" \
  --description "Read-only database analytics queries"

# Delete a custom profile (built-in presets are protected)
mcp-sentinel profile delete <NAME>
```

### `mcp-sentinel audit` (alias: `audits`)

Inspect and manage structured security audit logs. Audit logging is **Default OFF (opt-in)** and records events in JSON-Lines format with automatic 5MB log rotation.

> 🔒 **Security & Privacy Guarantee**: Audit logs **NEVER** record plaintext secret values under any circumstances (only secret key names are logged).

```bash
# List recent audit events in a formatted table
mcp-sentinel audit list

# View the last 50 events
mcp-sentinel audit list --limit 50

# Filter only blocked security events (blocked tool calls)
mcp-sentinel audit list --blocked-only

# Filter by specific event type (SERVER_START, TOOL_CALL_BLOCKED, TOFU_DECISION, etc.)
mcp-sentinel audit list --event TOOL_CALL_BLOCKED

# Check audit logging status, log file location, and entry counts
mcp-sentinel audit status

# Purge audit log history safely
mcp-sentinel audit clear
```

### `mcp-sentinel migrate`

Automatically scan and migrate existing plaintext MCP configuration files across all major AI agents and IDEs to Zero-Trust architecture. Extracts secrets into the native OS Keyring, eliminates plaintext credentials from disk, and wraps server commands with `mcp-sentinel`.

**Supported AI Agents & Clients**:
- **Claude**: Claude Desktop (`claude_desktop_config.json`) & Claude Code (`~/.claude.json`)
- **Cursor**: Global (`~/.cursor/mcp.json`) & Workspace (`.cursor/mcp.json`, `mcp.json`)
- **Antigravity**: Global (`~/.gemini/config/mcp_config.json`, `~/.gemini/antigravity-ide/mcp_config.json`) & Workspace (`.agents/mcp_config.json`, `.gemini/mcp_config.json`)
- **Kiro**: Global (`~/.kiro/settings/mcp.json`, `~/.kiro/crew/mcp.json`) & Workspace (`.kiro/mcp.json`)
- **Codex**: Global (`~/.codex/mcp.json`, `%APPDATA%\OpenAI\mcp.json`) & Workspace (`.codex/mcp.json`)
- **Windsurf**: Global (`~/.codeium/windsurf/mcp_config.json`)
- **Cline**: VS Code extension settings (`cline_mcp_settings.json`)
- **Roo Code**: VS Code extension settings (`cline_mcp_settings.json`)
- **VS Code**: Workspace MCP configs (`.vscode/mcp.json`)
- **Continue**: Global configuration (`~/.continue/config.json`)

```bash
# Auto-detect and migrate ALL supported AI agents installed on your machine
mcp-sentinel migrate

# Target a specific AI Agent or IDE
mcp-sentinel migrate antigravity
mcp-sentinel migrate kiro
mcp-sentinel migrate codex
mcp-sentinel migrate cursor
mcp-sentinel migrate claude
mcp-sentinel migrate windsurf
mcp-sentinel migrate cline
mcp-sentinel migrate roo
mcp-sentinel migrate vscode
mcp-sentinel migrate continue

# Migrate any custom configuration file directly
mcp-sentinel migrate --file /path/to/custom_mcp_config.json

# Preview migration without modifying files or OS vault
mcp-sentinel migrate --dry-run
```

- Automatically generates a `.bak` backup file before overwriting (can be skipped with `--no-backup`).
- Automatically resolves `${env:VAR}`, `${VAR}`, and `$VAR` from host environment so real credentials are encrypted in the vault.
- Intelligently preserves non-secret configuration variables using `--pass-env` to prevent DLP over-redaction.
- Full support for JSONC (JSON with comments and trailing commas).
- Safely resolves naming collisions by automatically generating isolated secret aliases and `SRV_` prefixes for colliding keys.
- Skips servers that are already protected by `mcp-sentinel`.

### `mcp-sentinel ui` (alias: `tui`, `dashboard`)

Launch the interactive Terminal User Interface (TUI) Dashboard for visual secret and permission management.

```bash
mcp-sentinel ui
```

* **Keyboard Navigation & Shortcuts:**
  * `[↑]` / `[↓]`: Navigate menu items in Sidebar or scroll view items in Content view (supports mouse wheel and smooth vertical scrolling for smaller screens and laptop displays)
  * `[Enter]`: Select menu item, reveal secret, or trigger action
  * `[→]` / `[Tab]`: Enter content view from sidebar
  * `[←]` / `[Esc]`: Return focus to sidebar menu
  * `[1]` / `[2]` / `[3]` / `[4]`: Quick jump to Secrets Vault, Permissions, Tool Policies, or System Status
  * `[a]`: Add new secret to OS Keyring
  * `[v]`: Reveal selected secret value in modal dialog
  * `[e]`: Edit / update selected secret value
  * `[d]` / `[Delete]`: Delete secret, revoke permission, or delete custom tool profile
  * `[r]`: Reload from OS Vault, permissions, and tool profiles
  * `[x]`: Reset all permissions
  * `[q]`: Quit dashboard

### `mcp-sentinel kill` (alias: `stop`)

Terminate all running `mcp-sentinel` proxy processes. Ideal for stopping background workers before performing an upgrade (e.g., via `cargo install --force` or `winget upgrade`) to avoid Windows executable file locks (`Access is denied (os error 5)`).

```bash
# Gracefully stop all running background mcp-sentinel processes
mcp-sentinel kill

# Or force-kill immediately
mcp-sentinel kill --force

# Alias command:
mcp-sentinel stop
```

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
8. **Layer 7 JSON-RPC Tool Firewall**: Intercepts `tools/call` requests on child process `stdin`. If an LLM or user attempts to call a tool blocked by the active profile or `--deny-tools` pattern, `mcp-sentinel` synthesizes a JSON-RPC `-32001` error response back to the host IDE, alerts `stderr`, and completely drops the request from reaching the child process.
9. **Opt-in Structured Audit Trail**: When enabled via `--audit` or `MCP_SENTINEL_AUDIT=1`, captures structured security events (`SERVER_START`, `TOOL_CALL_ALLOWED`, `TOOL_CALL_BLOCKED`, `TOFU_DECISION`, `SERVER_EXIT`) in JSON-Lines format. Default is OFF (zero disk footprint). Plaintext secret values are strictly stripped and never logged, and logs rotate automatically at 5MB.
10. **Verified by 135 Automated Tests across 7 Suites**:
   - **Unit Tests (77 tests)**: Vault operations, alias mapping & validation, fingerprint collision resistance, HMAC signing & tamper rejection for policies and tool profiles, wildcard pattern evaluation, multi-agent auto-migration path discovery, environment sanitizer whitelist, pass-env forwarding & dangerous variable blocking, dialog text sanitization & multi-byte UTF-8 preservation, interactive TUI navigation and widget state management, stream-boundary DLP redaction, JSON-escaped secret masking, Allow Once ephemeral grants, atomic file locking, and structured audit entry serialization.
   - **Security Penetration & Hacking Tests (31 tests)**: Host environment variable exfiltration blocked, command injection (`;&|`) neutralized, forged permission injection rejected, argument smuggling intercepted, child process sandbox recursion blocked, reserved key name rejection, alias tamper resistance, stdout DLP secret masking, Allow Once non-persistence, Layer 7 tool call firewall drops & error synthesis, multi-line formatted JSON-RPC firewall interception, batch request inspection, Unicode homoglyph & Trojan Source defense, stdin buffer DoS defense, grandchild pipe hang mitigation, dangerous runtime control variable blocking, and audit log default-off & secret leak immunity.
   - **Integration Tests (9 tests)**: Subprocess execution, CLI parsing, exit code propagation, secret list, permissions list, TUI launch commands, pass-env end-to-end propagation, and full migration workflow.
   - **Concurrency Tests (5 tests)**: Concurrent policy grants, vault key registrations, audit logging, and tool policy upserts under multi-threaded load.
   - **Fast-Path Tests (3 tests)**: Zero-copy raw bytes stream preservation for allowed single requests, batch requests, and mixed batch payload filtering.
   - **Stress Tests (6 tests)**: 100-secret bulk injection, corrupted policy resilience, Unicode & Vietnamese character preservation, stdio separation, and custom exit code propagation.
   - **Performance Benchmarks (4 tests)**: High-load async stdio streaming (~46,000+ JSON-RPC msgs/sec), multithreaded SHA-256 hashing (~8,000,000 ops/sec).

---

## 🛠️ Performance Metrics

Benchmark results measured under production release profile (`--release`):

| Metric | Measured Value | Notes & Context |
| :--- | :--- | :--- |
| **Stdio Streaming Throughput** | **~46,000 - 48,000 msgs/sec** | Fast-Path Zero-Copy proxying on 5,000 JSON-RPC ping frames |
| **Internal Initialization Latency** | **< 1.5 ms** | Keyring credential resolution, HMAC policy verification, and env sanitization |
| **SHA-256 Fingerprint Hashing** | **~1,400,000 ops/sec** | Single-threaded canonical command hashing (`~8,000,000 ops/sec` with 16 threads) |
| **Environment Sanitization** | **~6,500 ops/sec** | Full default-deny whitelist validation and safe-variable injection |
| **Memory Footprint (RSS)** | **~8.5 - 10.5 MB** | Peak Working Set during high-throughput bidirectional streaming |
| **Binary Size (Standard Edition)** | **~3.8 MB** | Fully standalone statically linked binary including modular Ratatui TUI dashboard |
| **Binary Size (Headless Edition)** | **~3.4 MB** | Micro-binary without TUI dependencies (`--no-default-features`), ideal for CI/CD & Docker |

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
No. Once authorized, <code>mcp-sentinel</code> acts as an ultra-fast asynchronous duplex stream proxy. It forwards raw bytes between <code>stdin</code> and <code>stdout</code> at over 46,000 messages per second with microsecond latency.
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
<summary><b>Can an autonomous AI model accidentally delete files or drop databases?</b></summary>
Not if protected by Sentinel. By specifying <code>--profile read-only</code>, <code>--profile no-destructive</code>, or inline rules like <code>--deny-tools "*delete*,*drop*"</code>, Sentinel's Layer 7 Tool Firewall intercepts destructive <code>tools/call</code> requests on <code>stdin</code> and drops them with a JSON-RPC <code>-32001</code> error before the child process can execute them.
</details>

<details>
<summary><b>How does Sentinel prevent malicious packages from hijacking child runtimes?</b></summary>
Attackers often try to use runtime flags (such as <code>NODE_OPTIONS="--require /tmp/malicious.js"</code> or <code>LD_PRELOAD</code>) to inject code before the main application starts. Sentinel automatically detects and strips all dangerous execution controls, even if requested via <code>--pass-env</code>.
</details>

<details>
<summary><b>Does mcp-sentinel require Administrator or Root privileges?</b></summary>
No. <code>mcp-sentinel</code> runs entirely in user-space, storing credentials inside your personal OS user vault (Windows Credential Manager, macOS Keychain, or Linux Secret Service). It strictly adheres to the principle of least privilege and does not require elevated rights.
</details>

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
