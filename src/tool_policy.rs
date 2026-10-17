use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const TOOL_POLICIES_FILE_NAME: &str = "tool_policies.json";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ToolProfile {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ToolPolicyFile {
    pub profiles: HashMap<String, ToolProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDecision {
    Allowed,
    Blocked { reason: String },
}

pub fn get_tool_policies_file_path() -> Result<PathBuf, String> {
    let config_dir = crate::policy::get_config_dir()?;
    Ok(config_dir.join(TOOL_POLICIES_FILE_NAME))
}

/// Returns the built-in preset tool profiles.
pub fn default_preset_profiles() -> HashMap<String, ToolProfile> {
    let mut map = HashMap::new();

    map.insert(
        "read-only".to_string(),
        ToolProfile {
            name: "read-only".to_string(),
            description: Some(
                "Allows read and query operations; denies destructive or modifying calls"
                    .to_string(),
            ),
            allow: vec![
                "get_*".to_string(),
                "read_*".to_string(),
                "list_*".to_string(),
                "search_*".to_string(),
                "describe_*".to_string(),
                "fetch_*".to_string(),
                "query_*".to_string(),
                "find_*".to_string(),
                "inspect_*".to_string(),
                "select_*".to_string(),
            ],
            deny: vec![
                "*delete*".to_string(),
                "*drop*".to_string(),
                "*remove*".to_string(),
                "*truncate*".to_string(),
                "*write*".to_string(),
                "*update*".to_string(),
                "*push*".to_string(),
                "*kill*".to_string(),
                "*exec*".to_string(),
                "*insert*".to_string(),
                "*alter*".to_string(),
                "*create*".to_string(),
                "*modify*".to_string(),
            ],
        },
    );

    map.insert(
        "no-destructive".to_string(),
        ToolProfile {
            name: "no-destructive".to_string(),
            description: Some(
                "Permits all standard operations; blocks high-risk destructive commands (drop, delete, truncate, purge)"
                    .to_string(),
            ),
            allow: vec![],
            deny: vec![
                "*drop*".to_string(),
                "*delete*".to_string(),
                "*truncate*".to_string(),
                "*destroy*".to_string(),
                "*purge*".to_string(),
                "*format*".to_string(),
                "*erase*".to_string(),
                "*wipe*".to_string(),
            ],
        },
    );

    map
}

/// Matches a string against a pattern supporting `*` and `?` wildcards (case-insensitive) with full backtracking.
pub fn matches_pattern(candidate: &str, pattern: &str) -> bool {
    let candidate = candidate.to_lowercase();
    let pattern = pattern.to_lowercase();

    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') && !pattern.contains('?') {
        return candidate == pattern;
    }

    let s_chars: Vec<char> = candidate.chars().collect();
    let p_chars: Vec<char> = pattern.chars().collect();
    let mut s_idx = 0;
    let mut p_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while s_idx < s_chars.len() {
        if p_idx < p_chars.len() && (p_chars[p_idx] == s_chars[s_idx] || p_chars[p_idx] == '?') {
            s_idx += 1;
            p_idx += 1;
        } else if p_idx < p_chars.len() && p_chars[p_idx] == '*' {
            star_idx = Some(p_idx);
            match_idx = s_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            s_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_chars.len() && p_chars[p_idx] == '*' {
        p_idx += 1;
    }

    p_idx == p_chars.len()
}

/// Evaluates whether an MCP tool call is permitted by a `ToolProfile`.
pub fn evaluate_tool_call(tool_name: &str, profile: &ToolProfile) -> ToolDecision {
    let tool_clean = tool_name.trim();

    // 1. Check Deny list (Deny always takes precedence for security)
    for pattern in &profile.deny {
        if matches_pattern(tool_clean, pattern) {
            return ToolDecision::Blocked {
                reason: format!("Matches deny pattern '{}'", pattern),
            };
        }
    }

    // 2. Check Allow list (if non-empty, tool MUST match at least one allowed pattern)
    if !profile.allow.is_empty() {
        let allowed = profile
            .allow
            .iter()
            .any(|pat| matches_pattern(tool_clean, pat));
        if !allowed {
            return ToolDecision::Blocked {
                reason: "Does not match any pattern in the allow whitelist".to_string(),
            };
        }
    }

    ToolDecision::Allowed
}

fn compute_file_signature(profiles: &HashMap<String, ToolProfile>) -> Result<String, String> {
    let master_key = crate::policy::get_or_create_master_key()?;
    let mut mac = HmacSha256::new_from_slice(&master_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;

    // Sort profile names deterministically
    let mut keys: Vec<&String> = profiles.keys().collect();
    keys.sort();

    for key in keys {
        let p = &profiles[key];
        mac.update(p.name.as_bytes());
        mac.update(b"|");
        if let Some(ref desc) = p.description {
            mac.update(desc.as_bytes());
        }
        mac.update(b"|ALLOW:");
        let mut sorted_allow = p.allow.clone();
        sorted_allow.sort();
        for a in &sorted_allow {
            mac.update(a.as_bytes());
            mac.update(b",");
        }
        mac.update(b"|DENY:");
        let mut sorted_deny = p.deny.clone();
        sorted_deny.sort();
        for d in &sorted_deny {
            mac.update(d.as_bytes());
            mac.update(b",");
        }
        mac.update(b"\n");
    }

    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Loads tool profiles from disk, verifying the cryptographic HMAC signature.
/// If no file exists, initializes with default preset profiles.
pub fn load_profiles() -> Result<ToolPolicyFile, String> {
    let file_path = get_tool_policies_file_path()?;
    if !file_path.exists() {
        let file = ToolPolicyFile {
            profiles: default_preset_profiles(),
            signature: None,
        };
        let _ = save_profiles(&file);
        return Ok(file);
    }

    let content = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;

    let file: ToolPolicyFile = serde_json::from_str(&content)
        .map_err(|e| format!("Corrupted tool policy file {}: {}", file_path.display(), e))?;

    // Verify HMAC-SHA256 signature
    let expected_sig = compute_file_signature(&file.profiles)?;
    match file.signature {
        Some(ref sig) if sig == &expected_sig => Ok(file),
        _ => {
            eprintln!(
                "[mcp-sentinel] Security Warning: Tampered or unsigned tool_policies.json detected! Discarding tampered file and restoring defaults."
            );
            let backup_path = file_path.with_extension("json.tampered");
            let _ = fs::rename(&file_path, backup_path);

            let fallback = ToolPolicyFile {
                profiles: default_preset_profiles(),
                signature: None,
            };
            let _ = save_profiles(&fallback);
            Ok(fallback)
        }
    }
}

/// Saves tool profiles to disk, computing and attaching an HMAC-SHA256 signature.
pub fn save_profiles(file: &ToolPolicyFile) -> Result<(), String> {
    let file_path = get_tool_policies_file_path()?;
    let mut to_save = file.clone();
    to_save.signature = Some(compute_file_signature(&to_save.profiles)?);

    let json = serde_json::to_string_pretty(&to_save)
        .map_err(|e| format!("Failed to serialize tool policy file: {}", e))?;

    fs::write(&file_path, json)
        .map_err(|e| format!("Failed to write {}: {}", file_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Retrieves a specific profile by name.
pub fn get_profile(name: &str) -> Option<ToolProfile> {
    load_profiles().ok()?.profiles.remove(name)
}

/// Creates or updates a profile.
pub fn upsert_profile(profile: ToolProfile) -> Result<(), String> {
    let mut file = load_profiles()?;
    file.profiles.insert(profile.name.clone(), profile);
    save_profiles(&file)
}

/// Deletes a profile by name.
pub fn delete_profile(name: &str) -> Result<bool, String> {
    let mut file = load_profiles()?;
    let removed = file.profiles.remove(name).is_some();
    if removed {
        save_profiles(&file)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern_exact_and_wildcard() {
        assert!(matches_pattern("read_file", "read_file"));
        assert!(matches_pattern("READ_FILE", "read_file"));
        assert!(matches_pattern("read_file", "read_*"));
        assert!(matches_pattern("read_query_result", "read_*"));
        assert!(!matches_pattern("write_file", "read_*"));
        assert!(matches_pattern("drop_table", "*drop*"));
        assert!(matches_pattern("admin_drop_database", "*drop*"));
        assert!(matches_pattern("delete", "*delete*"));
        assert!(matches_pattern("execute_sql", "*"));
        assert!(matches_pattern("ababc", "*ab*bc"));
        assert!(matches_pattern("axaybz", "*a*b*"));
        assert!(matches_pattern("tool_read", "?ool_*"));
        assert!(!matches_pattern("tool_read", "?ool"));
    }

    #[test]
    fn test_evaluate_tool_call_deny_overrides_allow() {
        let profile = ToolProfile {
            name: "test-profile".to_string(),
            description: None,
            allow: vec!["read_*".to_string(), "query_*".to_string()],
            deny: vec!["*delete*".to_string(), "*drop*".to_string()],
        };

        // Allowed
        assert_eq!(
            evaluate_tool_call("read_file", &profile),
            ToolDecision::Allowed
        );
        assert_eq!(
            evaluate_tool_call("query_users", &profile),
            ToolDecision::Allowed
        );

        // Denied via whitelist (not matching allow)
        match evaluate_tool_call("update_table", &profile) {
            ToolDecision::Blocked { reason } => {
                assert!(reason.contains("allow whitelist"));
            }
            _ => panic!("Expected update_table to be blocked"),
        }

        // Denied via blacklist
        match evaluate_tool_call("read_and_delete", &profile) {
            ToolDecision::Blocked { reason } => {
                assert!(reason.contains("Matches deny pattern"));
            }
            _ => panic!("Expected read_and_delete to be blocked by deny"),
        }
    }

    #[test]
    fn test_evaluate_tool_call_empty_allow_means_permit_unless_denied() {
        let profile = ToolProfile {
            name: "no-delete".to_string(),
            description: None,
            allow: vec![],
            deny: vec!["*delete*".to_string()],
        };

        assert_eq!(
            evaluate_tool_call("anything_else", &profile),
            ToolDecision::Allowed
        );
        assert!(matches!(
            evaluate_tool_call("delete_user", &profile),
            ToolDecision::Blocked { .. }
        ));
    }

    #[test]
    fn test_default_preset_profiles_contain_read_only() {
        let presets = default_preset_profiles();
        assert!(presets.contains_key("read-only"));
        assert!(presets.contains_key("no-destructive"));

        let ro = &presets["read-only"];
        assert_eq!(evaluate_tool_call("read_file", ro), ToolDecision::Allowed);
        assert!(matches!(
            evaluate_tool_call("drop_table", ro),
            ToolDecision::Blocked { .. }
        ));
    }

    #[test]
    fn test_tampered_or_unsigned_tool_policies_file_rejected() {
        let unsigned_json = r#"{
            "profiles": {
                "hacked": {
                    "name": "hacked",
                    "allow": ["*"],
                    "deny": []
                }
            },
            "signature": null
        }"#;

        let file: ToolPolicyFile = serde_json::from_str(unsigned_json).unwrap();
        let expected_sig = compute_file_signature(&file.profiles).unwrap();

        let is_valid = matches!(file.signature, Some(ref sig) if sig == &expected_sig);
        assert!(!is_valid, "Unsigned policy file must be rejected!");
    }
}
