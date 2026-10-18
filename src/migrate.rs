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

/// Transforms raw JSON content: extracts plaintext secrets into OS vault, wraps commands with mcp-sentinel,
/// and strips plaintext env vars from the JSON.
pub fn transform_config_json(
    json_str: &str,
    dry_run: bool,
) -> Result<(String, Vec<ServerMigrationResult>), String> {
    let mut root: Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON configuration: {}", e))?;

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

        // Extract secrets from plaintext "env" block
        if let Some(env_val) = server_obj.get("env").and_then(|e| e.as_object()) {
            for (env_key, val) in env_val {
                let raw_val_str = match val.as_str() {
                    Some(s) => s.to_string(),
                    None => val.to_string(),
                };
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

        new_args.push("--".to_string());
        new_args.push(orig_cmd.clone());
        new_args.extend(orig_args);

        // Update JSON with absolute path to mcp-sentinel binary to prevent spawn ENOENT in GUI apps
        let sentinel_bin = std::env::current_exe()
            .ok()
            .and_then(|p| {
                let file_name = p.file_name()?.to_str()?;
                if file_name == "mcp-sentinel" || file_name == "mcp-sentinel.exe" {
                    Some(p.to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "mcp-sentinel".to_string());
        server_obj.insert("command".to_string(), json!(sentinel_bin));
        server_obj.insert("args".to_string(), json!(new_args));
        server_obj.remove("env"); // Remove plaintext secrets from disk!

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
}
