use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrateTarget {
    Claude,
    Cursor,
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

    let check_claude = matches!(target, MigrateTarget::Claude | MigrateTarget::All);
    let check_cursor = matches!(target, MigrateTarget::Cursor | MigrateTarget::All);

    if let Some(base_dirs) = directories::BaseDirs::new() {
        if check_claude {
            // Windows: %APPDATA%\Claude\claude_desktop_config.json
            // macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
            // Linux: ~/.config/Claude/claude_desktop_config.json
            let claude_path = base_dirs
                .config_dir()
                .join("Claude")
                .join("claude_desktop_config.json");
            if claude_path.exists() {
                paths.push(claude_path);
            }
        }

        if check_cursor {
            // Global Cursor MCP config: ~/.cursor/mcp.json
            let cursor_home = base_dirs.home_dir().join(".cursor").join("mcp.json");
            if cursor_home.exists() {
                paths.push(cursor_home);
            }
        }
    }

    if check_cursor {
        // Project-level .cursor/mcp.json
        let local_cursor = PathBuf::from(".cursor").join("mcp.json");
        if local_cursor.exists() && !paths.contains(&local_cursor) {
            paths.push(local_cursor);
        }

        // Local mcp.json in current directory
        let local_mcp = PathBuf::from("mcp.json");
        if local_mcp.exists() && !paths.contains(&local_mcp) {
            paths.push(local_mcp);
        }
    }

    paths
}

/// Sanitizes an arbitrary string into a valid environment variable name.
fn sanitize_for_env_key(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "SECRET".to_string()
    } else {
        trimmed.to_string()
    }
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
                let val_str = match val.as_str() {
                    Some(s) => s.to_string(),
                    None => val.to_string(),
                };

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

        // Update JSON
        server_obj.insert("command".to_string(), json!("mcp-sentinel"));
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
            fs::write(&bak, &content)
                .map_err(|e| format!("Failed to create backup file '{}': {}", bak.display(), e))?;
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
        assert_eq!(sanitize_for_env_key("my-api-key"), "MY_API_KEY");
        assert_eq!(sanitize_for_env_key("token@service"), "TOKEN_SERVICE");
        assert_eq!(sanitize_for_env_key("___"), "SECRET");
    }
}
