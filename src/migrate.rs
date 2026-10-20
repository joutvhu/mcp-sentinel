use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrateTarget {
    Claude,
    Cursor,
    Antigravity,
    Kiro,
    Codex,
    Windsurf,
    Cline,
    #[value(alias = "roo")]
    RooCode,
    #[value(alias = "vscode")]
    VsCode,
    Continue,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMigrationResult {
    pub server_name: String,
    pub original_command: String,
    pub extracted_secrets: Vec<String>,
    pub already_migrated: bool,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct FileMigrationReport {
    pub file_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub results: Vec<ServerMigrationResult>,
}

/// Discovers candidate MCP config paths based on the requested target and operating system.
pub fn find_config_paths(target: MigrateTarget) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let mut add_if_exists = |path: PathBuf| {
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    };

    let check_claude = matches!(target, MigrateTarget::Claude | MigrateTarget::All);
    let check_cursor = matches!(target, MigrateTarget::Cursor | MigrateTarget::All);
    let check_antigravity = matches!(target, MigrateTarget::Antigravity | MigrateTarget::All);
    let check_kiro = matches!(target, MigrateTarget::Kiro | MigrateTarget::All);
    let check_codex = matches!(target, MigrateTarget::Codex | MigrateTarget::All);
    let check_windsurf = matches!(target, MigrateTarget::Windsurf | MigrateTarget::All);
    let check_cline = matches!(target, MigrateTarget::Cline | MigrateTarget::All);
    let check_roo = matches!(target, MigrateTarget::RooCode | MigrateTarget::All);
    let check_vscode = matches!(target, MigrateTarget::VsCode | MigrateTarget::All);
    let check_continue = matches!(target, MigrateTarget::Continue | MigrateTarget::All);

    if let Some(base_dirs) = directories::BaseDirs::new() {
        let home = base_dirs.home_dir();
        let config_dir = base_dirs.config_dir();

        if check_claude {
            // Windows: %APPDATA%\Claude\claude_desktop_config.json
            // macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
            // Linux: ~/.config/Claude/claude_desktop_config.json
            add_if_exists(config_dir.join("Claude").join("claude_desktop_config.json"));
            // Claude Code CLI
            add_if_exists(home.join(".claude.json"));
            add_if_exists(home.join(".claude").join("mcp.json"));
        }

        if check_cursor {
            // Global Cursor MCP config: ~/.cursor/mcp.json
            add_if_exists(home.join(".cursor").join("mcp.json"));
        }

        if check_antigravity {
            // Antigravity global configurations
            add_if_exists(home.join(".gemini").join("config").join("mcp_config.json"));
            add_if_exists(
                home.join(".gemini")
                    .join("antigravity-ide")
                    .join("mcp_config.json"),
            );
            add_if_exists(
                home.join(".gemini")
                    .join("antigravity")
                    .join("mcp_config.json"),
            );
        }

        if check_kiro {
            // Kiro global settings and crew configs
            add_if_exists(home.join(".kiro").join("settings").join("mcp.json"));
            add_if_exists(home.join(".kiro").join("crew").join("mcp.json"));
        }

        if check_codex {
            // OpenAI Codex CLI & Desktop configurations
            add_if_exists(home.join(".codex").join("mcp.json"));
            add_if_exists(config_dir.join("OpenAI").join("mcp.json"));
        }

        if check_windsurf {
            // Windsurf (Codeium) global config
            add_if_exists(
                home.join(".codeium")
                    .join("windsurf")
                    .join("mcp_config.json"),
            );
        }

        if check_cline {
            // Cline VS Code extension global settings
            add_if_exists(
                config_dir
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("saoudrizwan.claude-dev")
                    .join("settings")
                    .join("cline_mcp_settings.json"),
            );
        }

        if check_roo {
            // Roo Code extension global settings
            add_if_exists(
                config_dir
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("rooveterinaryinc.roo-cline")
                    .join("settings")
                    .join("cline_mcp_settings.json"),
            );
        }

        if check_continue {
            // Continue.dev global config
            add_if_exists(home.join(".continue").join("config.json"));
        }
    }

    // Workspace / Project-level configurations
    if check_cursor {
        add_if_exists(PathBuf::from(".cursor").join("mcp.json"));
        add_if_exists(PathBuf::from("mcp.json"));
    }

    if check_antigravity {
        add_if_exists(PathBuf::from(".agents").join("mcp_config.json"));
        add_if_exists(PathBuf::from(".gemini").join("mcp_config.json"));
    }

    if check_kiro {
        add_if_exists(PathBuf::from(".kiro").join("mcp.json"));
        add_if_exists(PathBuf::from(".kiro").join("settings").join("mcp.json"));
    }

    if check_codex {
        add_if_exists(PathBuf::from(".codex").join("mcp.json"));
    }

    if check_vscode {
        add_if_exists(PathBuf::from(".vscode").join("mcp.json"));
    }

    paths
}

/// Sanitizes an arbitrary string into a valid environment variable name,
/// preserving case-sensitivity and ensuring it begins with an ASCII letter or underscore.
fn sanitize_for_env_key(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        return "SECRET".to_string();
    }

    // Ensure the key starts with an ASCII letter or underscore (for vault validation)
    let first = trimmed.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        format!("_{}", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// If a value is an environment variable placeholder like `${env:VAR}`, `${VAR}`, or `$VAR`,
/// attempts to resolve it from the current process environment. Falls back to original value if unset.
fn resolve_env_placeholder(val: &str) -> String {
    let var_name = if val.starts_with("${env:") && val.ends_with('}') && val.len() > 7 {
        Some(&val[6..val.len() - 1])
    } else if val.starts_with("${") && val.ends_with('}') && val.len() > 3 {
        Some(&val[2..val.len() - 1])
    } else if val.starts_with('$') && !val.contains(' ') && val.len() > 1 {
        Some(&val[1..])
    } else {
        None
    };

    if let Some(name) = var_name {
        if let Ok(resolved) = std::env::var(name) {
            return resolved;
        }
    }
    val.to_string()
}

/// Strips single-line (`// ...`) and multi-line (`/* ... */`) comments from a JSON string,
/// preserving comment-like sequences inside string literals and keeping newlines intact.
pub fn strip_jsonc_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < len {
        if in_string {
            let b = bytes[i];
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
        } else if bytes[i] == b'"' {
            in_string = true;
            out.push(b'"');
            i += 1;
        } else if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            // Line comment: skip until newline or EOF
            i += 2;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            // Block comment: skip until */ or EOF
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push(b'\n'); // Preserve line breaks for accurate error reporting
                }
                i += 1;
            }
            if i + 1 < len {
                i += 2; // skip */
            } else {
                i = len; // unclosed comment at EOF
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Strips trailing commas before `}` or `]` from a comment-free JSON string.
pub fn strip_trailing_commas(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < len {
        if in_string {
            let b = bytes[i];
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
        } else {
            let b = bytes[i];
            if b == b'"' {
                in_string = true;
                out.push(b);
                i += 1;
            } else if b == b',' {
                // Lookahead past ASCII whitespace and redundant commas
                let mut j = i + 1;
                while j < len
                    && (bytes[j] == b' '
                        || bytes[j] == b'\t'
                        || bytes[j] == b'\r'
                        || bytes[j] == b'\n'
                        || bytes[j] == b',')
                {
                    j += 1;
                }
                if j < len && (bytes[j] == b'}' || bytes[j] == b']') {
                    // Trailing comma before closing brace/bracket: drop it
                    i += 1;
                } else {
                    out.push(b);
                    i += 1;
                }
            } else {
                out.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Preprocesses JSONC text by removing line comments (`//`), block comments (`/* */`),
/// and trailing commas, making it valid standard JSON for `serde_json`.
pub fn clean_jsonc(input: &str) -> String {
    let stripped = strip_jsonc_comments(input);
    strip_trailing_commas(&stripped)
}

/// Returns true if the string is formatted as an environment variable placeholder
/// such as `${env:VAR}`, `${VAR}`, or `$VAR`.
pub fn is_placeholder_value(val: &str) -> bool {
    let trimmed = val.trim();
    (trimmed.starts_with("${env:") && trimmed.ends_with('}') && trimmed.len() > 7)
        || (trimmed.starts_with("${") && trimmed.ends_with('}') && trimmed.len() > 3)
        || (trimmed.starts_with('$') && !trimmed.contains(' ') && trimmed.len() > 1)
}

/// Returns true if a key name indicates a non-secret configuration setting
/// (such as URLs, file paths, directories, ports, hosts, regions, levels, etc.)
/// that must not be extracted to Vault Keyring or added to DLP redaction.
pub fn is_non_secret_config_key(key: &str) -> bool {
    let upper = key.to_uppercase();

    // Explicit config suffixes that override sensitive keywords if present at the end
    // (e.g. AUTH_URL, KEY_FILE, CERT_PATH, SECRET_DIR are paths/endpoints, not secrets)
    const CONFIG_SUFFIXES: &[&str] = &[
        "_URL",
        "_URI",
        "_ENDPOINT",
        "_PATH",
        "_DIR",
        "_DIRECTORY",
        "_FOLDER",
        "_FILE",
        "_FILENAME",
        "_HOST",
        "_HOSTNAME",
        "_PORT",
        "_REGION",
        "_ZONE",
        "_NAME",
        "_LEVEL",
        "_MODE",
        "_ENV",
        "_ENVIRONMENT",
        "_STAGE",
        "_TIMEOUT",
        "_INTERVAL",
        "_TTL",
        "_RETRY",
        "_RETRIES",
        "_LIMIT",
        "_ENABLED",
        "_DISABLED",
        "_FLAG",
        "_DEBUG",
        "_VERBOSE",
        "_VERSION",
        "_COUNT",
        "_SIZE",
    ];

    const CONFIG_EXACT: &[&str] = &[
        "URL", "URI", "ENDPOINT", "PATH", "DIR", "DIRECTORY", "FOLDER", "FILE",
        "HOST", "HOSTNAME", "PORT", "REGION", "ZONE", "NAME", "LEVEL", "MODE",
        "ENV", "ENVIRONMENT", "STAGE", "DEBUG", "VERBOSE", "TIMEOUT", "VERSION",
        "NO_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
    ];

    if CONFIG_EXACT.contains(&upper.as_str()) {
        return true;
    }

    if upper.contains("BYPASS") {
        return true;
    }

    for suffix in CONFIG_SUFFIXES {
        if upper.ends_with(suffix) {
            return true;
        }
    }

    false
}

/// Returns true if the key name indicates it likely holds a secret (credential, token, password, etc.)
pub fn is_likely_secret_key(key: &str) -> bool {
    if is_non_secret_config_key(key) {
        return false;
    }

    let upper = key.to_uppercase();

    // Sensitive keyword checks
    if upper.contains("KEY")
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("PASSPHRASE")
        || upper.contains("AUTH")
        || upper.contains("CREDENTIAL")
        || upper.contains("PRIVATE")
        || upper.contains("CERT")
        || upper.contains("SIGNING")
        || upper.contains("APIKEY")
        || upper.contains("BEARER")
        || upper.contains("SESSION")
        || upper.contains("SIGNATURE")
        || upper.contains("SALT")
        || upper.contains("ENCRYPTION")
    {
        return true;
    }

    // Special handling for PASS: ends with _PASS, starts with PASS_, or equals PASS
    if upper == "PASS" || upper.starts_with("PASS_") || upper.ends_with("_PASS") {
        return true;
    }

    false
}

/// Returns true if a key-value pair represents a secret that should be migrated to Vault Keyring
/// and passed via --secrets to mcp-sentinel.
pub fn is_likely_secret(key: &str, raw_val: &str) -> bool {
    // Non-secret configs (URLs, paths, dirs, ports, levels, etc.) must NEVER be treated as secrets
    if is_non_secret_config_key(key) {
        return false;
    }

    if is_likely_secret_key(key) {
        return true;
    }

    if is_placeholder_value(raw_val) {
        return true;
    }

    false
}

/// Transforms raw JSON content: extracts plaintext secrets into OS vault, wraps commands with mcp-sentinel,
/// and strips plaintext env vars from the JSON.
pub fn transform_config_json(
    json_str: &str,
    dry_run: bool,
) -> Result<(String, Vec<ServerMigrationResult>), String> {
    let cleaned = clean_jsonc(json_str);
    let mut root: Value =
        serde_json::from_str(&cleaned).map_err(|e| format!("Invalid JSON configuration: {}", e))?;

    let servers = root
        .get_mut("mcpServers")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "No 'mcpServers' object found in configuration".to_string())?;

    let mut results = Vec::new();

    for (server_name, server_val) in servers.iter_mut() {
        let server_obj = match server_val.as_object_mut() {
            Some(obj) => obj,
            None => continue,
        };

        let orig_cmd = match server_obj.get("command").and_then(|c| c.as_str()) {
            Some(c) => c.to_string(),
            None => continue,
        };

        // Check if already migrated
        let is_already_sentinel = orig_cmd == "mcp-sentinel"
            || orig_cmd.ends_with("/mcp-sentinel")
            || orig_cmd.ends_with("\\mcp-sentinel")
            || orig_cmd.ends_with("/mcp-sentinel.exe")
            || orig_cmd.ends_with("\\mcp-sentinel.exe");

        if is_already_sentinel {
            results.push(ServerMigrationResult {
                server_name: server_name.clone(),
                original_command: orig_cmd,
                extracted_secrets: Vec::new(),
                already_migrated: true,
                status: "Already protected with mcp-sentinel".to_string(),
            });
            continue;
        }

        let orig_args: Vec<String> = server_obj
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let mut secret_specs = Vec::new();
        let mut extracted_keys = Vec::new();
        let mut retained_env = serde_json::Map::new();

        // Extract secrets from plaintext "env" block, retaining non-secret configs
        if let Some(env_val) = server_obj.get("env").and_then(|e| e.as_object()) {
            for (env_key, val) in env_val {
                let raw_val_str = match val.as_str() {
                    Some(s) => s.to_string(),
                    None => val.to_string(),
                };

                if is_likely_secret(env_key, &raw_val_str) {
                    let val_str = resolve_env_placeholder(&raw_val_str);
                    let clean_key = sanitize_for_env_key(env_key);

                    // Determine vault storage key
                    let mut vault_key = clean_key.clone();
                    if let Ok(existing) = crate::vault::get_secret(&vault_key) {
                        if existing != val_str {
                            // Key exists with a different value -> create a dedicated alias to avoid collision
                            let server_prefix = sanitize_for_env_key(server_name);
                            vault_key = format!("{}_{}", server_prefix, clean_key);
                        }
                    }

                    // Avoid collision with reserved sentinel prefixes
                    if vault_key.to_uppercase().starts_with("MCP_SENTINEL")
                        || vault_key.starts_with("__")
                    {
                        vault_key = format!("SRV_{}", vault_key);
                    }

                    if !dry_run {
                        crate::vault::set_secret(&vault_key, &val_str).map_err(|e| {
                            format!("Failed to store secret '{}' in Keyring: {}", vault_key, e)
                        })?;
                    }

                    extracted_keys.push(vault_key.clone());

                    if clean_key == vault_key {
                        secret_specs.push(clean_key);
                    } else {
                        secret_specs.push(format!("{}={}", clean_key, vault_key));
                    }
                } else {
                    retained_env.insert(env_key.clone(), val.clone());
                }
            }
        }

        // Construct new arguments
        let mut new_args = vec!["run".to_string()];
        new_args.push("--name".to_string());
        new_args.push(format!("{} MCP Server", server_name));

        if !secret_specs.is_empty() {
            new_args.push("--secrets".to_string());
            new_args.push(secret_specs.join(","));
        }

        if !retained_env.is_empty() {
            let mut pass_keys: Vec<String> = retained_env.keys().cloned().collect();
            pass_keys.sort();
            new_args.push("--pass-env".to_string());
            new_args.push(pass_keys.join(","));
        }

        new_args.push("--".to_string());
        new_args.push(orig_cmd.clone());
        new_args.extend(orig_args);

        // Update JSON with absolute path to mcp-sentinel binary to prevent spawn ENOENT in GUI apps
        let sentinel_bin = std::env::current_exe()
            .ok()
            .and_then(|p| {
                let file_name = p.file_name()?.to_str()?;
                if file_name.eq_ignore_ascii_case("mcp-sentinel")
                    || file_name.eq_ignore_ascii_case("mcp-sentinel.exe")
                {
                    Some(p.to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "mcp-sentinel".to_string());
        server_obj.insert("command".to_string(), json!(sentinel_bin));
        server_obj.insert("args".to_string(), json!(new_args));

        if retained_env.is_empty() {
            server_obj.remove("env"); // Remove plaintext secrets from disk
        } else {
            server_obj.insert("env".to_string(), Value::Object(retained_env)); // Retain non-secret configs
        }

        let status = if secret_specs.is_empty() {
            "Isolated with mcp-sentinel (no secrets required)".to_string()
        } else {
            format!(
                "Migrated {} secret(s) to OS Keyring and secured with mcp-sentinel",
                secret_specs.len()
            )
        };

        results.push(ServerMigrationResult {
            server_name: server_name.clone(),
            original_command: orig_cmd,
            extracted_secrets: extracted_keys,
            already_migrated: false,
            status,
        });
    }

    let modified_json = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize transformed JSON: {}", e))?;

    Ok((modified_json, results))
}

/// Migrates a specific configuration file, creating a .bak backup before writing.
pub fn migrate_file(
    file_path: &Path,
    dry_run: bool,
    no_backup: bool,
) -> Result<FileMigrationReport, String> {
    if !file_path.exists() {
        return Err(format!("File '{}' does not exist", file_path.display()));
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read '{}': {}", file_path.display(), e))?;

    let (transformed_json, results) = transform_config_json(&content, dry_run)?;

    let mut backup_path = None;

    if !dry_run {
        if !no_backup {
            let bak = file_path.with_extension("json.bak");
            #[cfg(unix)]
            {
                use std::fs::OpenOptions;
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                use std::os::unix::fs::PermissionsExt;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&bak)
                    .map_err(|e| format!("Failed to create backup file '{}': {}", bak.display(), e))?;
                file.write_all(content.as_bytes())
                    .map_err(|e| format!("Failed to write backup file '{}': {}", bak.display(), e))?;
                let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                fs::write(&bak, &content)
                    .map_err(|e| format!("Failed to create backup file '{}': {}", bak.display(), e))?;
            }
            eprintln!(
                "[mcp-sentinel] Security Warning: Backup configuration file '{}' contains plaintext secrets! Please inspect and securely delete it once verified.",
                bak.display()
            );
            backup_path = Some(bak);
        }

        fs::write(file_path, transformed_json).map_err(|e| {
            format!(
                "Failed to write updated file '{}': {}",
                file_path.display(),
                e
            )
        })?;
    }

    Ok(FileMigrationReport {
        file_path: file_path.to_path_buf(),
        backup_path,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_config_json_with_secrets() {
        let input_json = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {
                        "GITHUB_TOKEN": "ghp_mock_123456"
                    }
                }
            }
        }"#;

        let (output_json, results) = transform_config_json(input_json, true).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "github");
        assert_eq!(results[0].extracted_secrets, vec!["GITHUB_TOKEN"]);
        assert!(!results[0].already_migrated);

        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        let gh = &parsed["mcpServers"]["github"];

        assert_eq!(gh["command"], "mcp-sentinel");
        assert!(gh.get("env").is_none(), "Plaintext env must be deleted");

        let args = gh["args"].as_array().unwrap();
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "--name");
        assert_eq!(args[2], "github MCP Server");
        assert_eq!(args[3], "--secrets");
        assert_eq!(args[4], "GITHUB_TOKEN");
        assert_eq!(args[5], "--");
        assert_eq!(args[6], "npx");
        assert_eq!(args[7], "-y");
        assert_eq!(args[8], "@modelcontextprotocol/server-github");
    }

    #[test]
    fn test_transform_config_json_already_migrated() {
        let input_json = r#"{
            "mcpServers": {
                "github": {
                    "command": "mcp-sentinel",
                    "args": ["run", "--secrets", "GITHUB_TOKEN", "--", "npx", "server"]
                }
            }
        }"#;

        let (output_json, results) = transform_config_json(input_json, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].already_migrated);
        assert_eq!(results[0].extracted_secrets.len(), 0);

        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        assert_eq!(parsed["mcpServers"]["github"]["command"], "mcp-sentinel");
    }

    #[test]
    fn test_transform_config_json_no_servers() {
        let input_json = r#"{"otherKey": 123}"#;
        let res = transform_config_json(input_json, true);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("No 'mcpServers' object"));
    }

    #[test]
    fn test_sanitize_for_env_key() {
        assert_eq!(sanitize_for_env_key("my-api-key"), "my_api_key");
        assert_eq!(sanitize_for_env_key("token@service"), "token_service");
        assert_eq!(sanitize_for_env_key("apiKey"), "apiKey");
        assert_eq!(sanitize_for_env_key("1PASSWORD_KEY"), "_1PASSWORD_KEY");
        assert_eq!(sanitize_for_env_key("___"), "SECRET");
    }

    #[test]
    fn test_find_config_paths_all_targets() {
        let targets = [
            MigrateTarget::Claude,
            MigrateTarget::Cursor,
            MigrateTarget::Antigravity,
            MigrateTarget::Kiro,
            MigrateTarget::Codex,
            MigrateTarget::Windsurf,
            MigrateTarget::Cline,
            MigrateTarget::RooCode,
            MigrateTarget::VsCode,
            MigrateTarget::Continue,
            MigrateTarget::All,
        ];
        for t in targets {
            let paths = find_config_paths(t);
            // Verify no duplicate paths returned
            let mut unique = std::collections::HashSet::new();
            for p in paths {
                assert!(unique.insert(p), "Found duplicate path in search results");
            }
        }
    }

    #[test]
    fn test_resolve_env_placeholder() {
        std::env::set_var("TEST_SENTINEL_ENV_EXPAND", "my_real_secret_token_999");

        // Format: ${env:VAR}
        assert_eq!(
            resolve_env_placeholder("${env:TEST_SENTINEL_ENV_EXPAND}"),
            "my_real_secret_token_999"
        );

        // Format: ${VAR}
        assert_eq!(
            resolve_env_placeholder("${TEST_SENTINEL_ENV_EXPAND}"),
            "my_real_secret_token_999"
        );

        // Format: $VAR
        assert_eq!(
            resolve_env_placeholder("$TEST_SENTINEL_ENV_EXPAND"),
            "my_real_secret_token_999"
        );

        // Non-existent variable falls back to literal string
        assert_eq!(
            resolve_env_placeholder("${env:NON_EXISTENT_VAR_XYZ}"),
            "${env:NON_EXISTENT_VAR_XYZ}"
        );

        // Regular literal string remains untouched
        assert_eq!(
            resolve_env_placeholder("plaintext_password_123"),
            "plaintext_password_123"
        );
    }

    #[test]
    fn test_migrate_file_backup_creation_and_permissions() {
        let temp_dir = std::env::temp_dir().join(format!("mcp_test_bak_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let config_file = temp_dir.join("test_config.json");
        let initial_json = r#"{
            "mcpServers": {
                "test": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": { "TEST_MIGRATE_KEY": "secret_val_123" }
                }
            }
        }"#;
        fs::write(&config_file, initial_json).unwrap();

        let report = migrate_file(&config_file, false, false).unwrap();
        assert!(report.backup_path.is_some());
        let bak = report.backup_path.unwrap();
        assert!(bak.exists());
        assert_eq!(fs::read_to_string(&bak).unwrap(), initial_json);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&bak).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Backup file permissions must be 0o600");
        }

        // Clean up
        let _ = fs::remove_file(&config_file);
        let _ = fs::remove_file(&bak);
        let _ = fs::remove_dir(&temp_dir);
        let _ = crate::vault::delete_secret("TEST_MIGRATE_KEY");
    }

    #[test]
    fn test_strip_jsonc_comments_and_trailing_commas() {
        let jsonc = r#"// Top-level comment
        {
            /* Block comment on servers */
            "mcpServers": {
                // Line comment for server
                "github": {
                    "command": "npx", // Inline comment
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-github", /* inline block */
                    ],
                    "env": {
                        "GITHUB_TOKEN": "ghp_mock_123456",
                        "URL": "https://example.com/api//v1/*not_a_comment*/",
                        "ESCAPED": "say \"hello // world\"",
                    },
                },
            },
        }
        // Bottom-level comment"#;

        let cleaned = clean_jsonc(jsonc);
        let parsed: Result<Value, _> = serde_json::from_str(&cleaned);
        assert!(parsed.is_ok(), "Failed to parse cleaned JSONC: {:?}", parsed.err());

        let val = parsed.unwrap();
        assert_eq!(
            val["mcpServers"]["github"]["env"]["URL"],
            "https://example.com/api//v1/*not_a_comment*/"
        );
        assert_eq!(
            val["mcpServers"]["github"]["env"]["ESCAPED"],
            "say \"hello // world\""
        );
    }

    #[test]
    fn test_transform_config_json_with_jsonc() {
        let jsonc = r#"{
            // Server configuration with comments and trailing commas
            "mcpServers": {
                /* Postgres database */
                "postgres": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-postgres",
                    ], // trailing comma in args
                    "env": {
                        "DATABASE_URL": "postgresql://localhost:5432/db", // line comment
                        "POSTGRES_PASSWORD": "secret_password_123",
                    }, // trailing comma in env
                },
            }, // trailing comma in mcpServers
        }"#;

        let (output_json, results) = transform_config_json(jsonc, true).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "postgres");
        assert_eq!(results[0].extracted_secrets, vec!["POSTGRES_PASSWORD"]);
        assert!(!results[0].already_migrated);

        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        let pg = &parsed["mcpServers"]["postgres"];
        assert_eq!(pg["command"], "mcp-sentinel");
        assert!(pg.get("env").is_some());
        assert_eq!(pg["env"]["DATABASE_URL"], "postgresql://localhost:5432/db");
        assert!(pg["env"].get("POSTGRES_PASSWORD").is_none());

        let args = pg["args"].as_array().unwrap();
        assert!(args.contains(&Value::String("--secrets".to_string())));
        assert!(args.contains(&Value::String("POSTGRES_PASSWORD".to_string())));
        assert!(args.contains(&Value::String("--pass-env".to_string())));
        assert!(args.contains(&Value::String("DATABASE_URL".to_string())));
    }

    #[test]
    fn test_is_likely_secret_heuristics() {
        // Secrets
        assert!(is_likely_secret_key("GITHUB_TOKEN"));
        assert!(is_likely_secret_key("OPENAI_API_KEY"));
        assert!(is_likely_secret_key("DB_PASSWORD"));
        assert!(is_likely_secret_key("REDIS_PASS"));
        assert!(is_likely_secret_key("CLIENT_SECRET"));
        assert!(is_likely_secret_key("AUTH_HEADER"));
        assert!(is_likely_secret_key("AWS_SECRET_ACCESS_KEY"));
        assert!(is_likely_secret_key("PRIVATE_KEY"));
        assert!(is_likely_secret_key("SSL_CERT"));
        assert!(is_likely_secret_key("SESSION_TOKEN"));
        assert!(is_likely_secret_key("ENCRYPTION_SALT"));
        assert!(is_likely_secret_key("APIKEY"));

        // Configs (must NOT be treated as secret keys)
        assert!(!is_likely_secret_key("GITHUB_API_URL"));
        assert!(!is_likely_secret_key("WORKSPACE_PATH"));
        assert!(!is_likely_secret_key("WORKSPACE_DIR"));
        assert!(!is_likely_secret_key("AWS_REGION"));
        assert!(!is_likely_secret_key("LOG_LEVEL"));
        assert!(!is_likely_secret_key("DB_NAME"));
        assert!(!is_likely_secret_key("PORT"));
        assert!(!is_likely_secret_key("HOST"));
        assert!(!is_likely_secret_key("NODE_ENV"));
        assert!(!is_likely_secret_key("REQUEST_TIMEOUT"));
        assert!(!is_likely_secret_key("BYPASS_PROXY"));
        assert!(!is_likely_secret_key("AUTH_URL"));
        assert!(!is_likely_secret_key("KEY_FILE"));
        assert!(!is_likely_secret_key("CERT_PATH"));

        // Placeholders
        assert!(is_placeholder_value("${env:SECRET_KEY}"));
        assert!(is_placeholder_value("${SECRET_KEY}"));
        assert!(is_placeholder_value("$SECRET_KEY"));
        assert!(!is_placeholder_value("https://api.github.com"));
        assert!(!is_placeholder_value("/path/to/folder"));
        assert!(!is_placeholder_value("debug"));

        // Combined is_likely_secret
        assert!(is_likely_secret("GITHUB_TOKEN", "ghp_123456"));
        assert!(is_likely_secret("OPENAI_API_KEY", "sk-123456"));
        assert!(is_likely_secret("DB_PASSWORD", "secret_pass"));
        assert!(is_likely_secret("CUSTOM_PARAM", "${env:MY_SECRET}"));

        assert!(!is_likely_secret("GITHUB_API_URL", "https://api.github.com"));
        assert!(!is_likely_secret("WORKSPACE_PATH", "/home/user/project"));
        assert!(!is_likely_secret("LOG_LEVEL", "debug"));
        assert!(!is_likely_secret("GITHUB_API_URL", "${env:GITHUB_API_URL}"));
        assert!(!is_likely_secret("WORKSPACE_DIR", "${env:WORKSPACE_DIR}"));
    }

    #[test]
    fn test_transform_config_json_mixed_env() {
        let input_json = r#"{
            "mcpServers": {
                "mixed_server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "GITHUB_TOKEN": "ghp_mock_123456",
                        "OPENAI_API_KEY": "sk-mock-987654",
                        "DB_PASSWORD": "db_secret_pass",
                        "GITHUB_API_URL": "https://api.github.com",
                        "WORKSPACE_PATH": "/path/to/workspace",
                        "LOG_LEVEL": "debug"
                    }
                }
            }
        }"#;

        let (output_json, results) = transform_config_json(input_json, true).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "mixed_server");

        // Exactly 3 secrets should be extracted
        assert_eq!(results[0].extracted_secrets.len(), 3);
        assert!(results[0].extracted_secrets.contains(&"GITHUB_TOKEN".to_string()));
        assert!(results[0].extracted_secrets.contains(&"OPENAI_API_KEY".to_string()));
        assert!(results[0].extracted_secrets.contains(&"DB_PASSWORD".to_string()));
        assert!(!results[0].extracted_secrets.contains(&"GITHUB_API_URL".to_string()));
        assert!(!results[0].extracted_secrets.contains(&"WORKSPACE_PATH".to_string()));
        assert!(!results[0].extracted_secrets.contains(&"LOG_LEVEL".to_string()));

        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        let server = &parsed["mcpServers"]["mixed_server"];

        assert_eq!(server["command"], "mcp-sentinel");

        // The 3 configs MUST be retained in "env"
        let env_obj = server["env"].as_object().unwrap();
        assert_eq!(env_obj.len(), 3);
        assert_eq!(env_obj["GITHUB_API_URL"], "https://api.github.com");
        assert_eq!(env_obj["WORKSPACE_PATH"], "/path/to/workspace");
        assert_eq!(env_obj["LOG_LEVEL"], "debug");

        // The 3 secrets MUST be removed from "env"
        assert!(!env_obj.contains_key("GITHUB_TOKEN"));
        assert!(!env_obj.contains_key("OPENAI_API_KEY"));
        assert!(!env_obj.contains_key("DB_PASSWORD"));

        // --secrets flag should contain the 3 secrets
        let args = server["args"].as_array().unwrap();
        let secrets_idx = args.iter().position(|a| a == "--secrets").unwrap();
        let secrets_val = args[secrets_idx + 1].as_str().unwrap();
        assert!(secrets_val.contains("GITHUB_TOKEN"));
        assert!(secrets_val.contains("OPENAI_API_KEY"));
        assert!(secrets_val.contains("DB_PASSWORD"));
        assert!(!secrets_val.contains("GITHUB_API_URL"));

        // --pass-env flag should contain the 3 retained configs sorted
        let pass_env_idx = args.iter().position(|a| a == "--pass-env").unwrap();
        let pass_env_val = args[pass_env_idx + 1].as_str().unwrap();
        assert_eq!(pass_env_val, "GITHUB_API_URL,LOG_LEVEL,WORKSPACE_PATH");
    }

    #[test]
    fn test_transform_config_json_config_only_env() {
        let input_json = r#"{
            "mcpServers": {
                "config_only_server": {
                    "command": "python",
                    "args": ["-m", "server"],
                    "env": {
                        "GITHUB_API_URL": "https://api.github.com",
                        "WORKSPACE_DIR": "/path/to/dir",
                        "AWS_REGION": "us-west-2",
                        "LOG_LEVEL": "info"
                    }
                }
            }
        }"#;

        let (output_json, results) = transform_config_json(input_json, true).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "config_only_server");
        assert_eq!(results[0].extracted_secrets.len(), 0);
        assert_eq!(results[0].status, "Isolated with mcp-sentinel (no secrets required)");

        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        let server = &parsed["mcpServers"]["config_only_server"];

        assert_eq!(server["command"], "mcp-sentinel");

        // All configs preserved in "env"
        let env_obj = server["env"].as_object().unwrap();
        assert_eq!(env_obj.len(), 4);
        assert_eq!(env_obj["GITHUB_API_URL"], "https://api.github.com");
        assert_eq!(env_obj["WORKSPACE_DIR"], "/path/to/dir");
        assert_eq!(env_obj["AWS_REGION"], "us-west-2");
        assert_eq!(env_obj["LOG_LEVEL"], "info");

        // --secrets flag should NOT be present in args
        let args = server["args"].as_array().unwrap();
        assert!(!args.iter().any(|a| a == "--secrets"));

        // --pass-env flag SHOULD be present in args with sorted keys
        let pass_env_idx = args.iter().position(|a| a == "--pass-env").unwrap();
        let pass_env_val = args[pass_env_idx + 1].as_str().unwrap();
        assert_eq!(pass_env_val, "AWS_REGION,GITHUB_API_URL,LOG_LEVEL,WORKSPACE_DIR");
    }

    #[test]
    fn test_transform_config_json_pass_env_formatting_and_sorting() {
        let input_json = r#"{
            "mcpServers": {
                "srv": {
                    "command": "node",
                    "args": ["index.js"],
                    "env": {
                        "ZEBRA": "1",
                        "APPLE": "2",
                        "MANGO": "3"
                    }
                }
            }
        }"#;

        let (output_json, _) = transform_config_json(input_json, true).unwrap();
        let parsed: Value = serde_json::from_str(&output_json).unwrap();
        let args = parsed["mcpServers"]["srv"]["args"].as_array().unwrap();
        let pass_env_idx = args.iter().position(|a| a == "--pass-env").unwrap();
        let pass_env_val = args[pass_env_idx + 1].as_str().unwrap();
        assert_eq!(pass_env_val, "APPLE,MANGO,ZEBRA");
    }
}
