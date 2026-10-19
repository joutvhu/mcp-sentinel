use directories::BaseDirs;
use keyring::Entry;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub const SERVICE_NAME: &str = "mcp-sentinel";

pub fn get_vault_keys_file_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("MCP_SENTINEL_CONFIG_DIR") {
        let dir = PathBuf::from(custom);
        let _ = fs::create_dir_all(&dir);
        return Some(dir.join("vault_keys.json"));
    }
    let base_dirs = BaseDirs::new()?;
    let config_dir = base_dirs.config_dir().join(SERVICE_NAME);
    let _ = fs::create_dir_all(&config_dir);
    Some(config_dir.join("vault_keys.json"))
}

pub fn get_vault_keys_lock_path() -> Option<PathBuf> {
    let path = get_vault_keys_file_path()?;
    Some(path.with_file_name("vault_keys.json.lock"))
}

fn list_keys_unlocked(path: &std::path::Path) -> BTreeSet<String> {
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(keys) = serde_json::from_str::<BTreeSet<String>>(&content) {
            return keys;
        }
    }
    BTreeSet::new()
}

pub fn list_keys() -> Vec<String> {
    if let Some(path) = get_vault_keys_file_path() {
        list_keys_unlocked(&path).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Validates that a secret key name conforms to safe environment variable identifier rules
/// and does not collide with internal sentinel reserved variables.
pub fn validate_key_name(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Secret key name cannot be empty".to_string());
    }
    if key.len() > 128 {
        return Err("Secret key name cannot exceed 128 characters".to_string());
    }
    if key.starts_with("__") || key.to_uppercase().starts_with("MCP_SENTINEL") {
        return Err(format!(
            "Secret key '{}' uses a reserved prefix ('__' or 'MCP_SENTINEL')",
            key
        ));
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(format!(
            "Secret key '{}' must start with an ASCII letter or underscore",
            key
        ));
    }
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(format!(
                "Secret key '{}' contains invalid character '{}'. Only alphanumeric characters and underscores are allowed.",
                key, c
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretMapping {
    pub target_env: String,
    pub vault_key: String,
}

impl SecretMapping {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err("Secret specification cannot be empty".to_string());
        }

        if let Some((target, vault)) = trimmed.split_once('=') {
            let target = target.trim();
            let vault = vault.trim();
            validate_key_name(target)
                .map_err(|e| format!("Invalid target environment variable '{}': {}", target, e))?;
            validate_key_name(vault)
                .map_err(|e| format!("Invalid vault secret key '{}': {}", vault, e))?;
            Ok(Self {
                target_env: target.to_string(),
                vault_key: vault.to_string(),
            })
        } else {
            validate_key_name(trimmed)?;
            Ok(Self {
                target_env: trimmed.to_string(),
                vault_key: trimmed.to_string(),
            })
        }
    }

    pub fn canonical_spec(&self) -> String {
        if self.target_env == self.vault_key {
            self.target_env.clone()
        } else {
            format!("{}={}", self.target_env, self.vault_key)
        }
    }

    pub fn display_label(&self) -> String {
        if self.target_env == self.vault_key {
            self.target_env.clone()
        } else {
            format!("{} (from vault: {})", self.target_env, self.vault_key)
        }
    }
}

/// Parses and validates a list of secret specifications, rejecting duplicate target environment variables.
pub fn parse_specs(specs: &[String]) -> Result<Vec<SecretMapping>, String> {
    let mut mappings = Vec::new();
    let mut seen_targets = std::collections::HashSet::new();
    for spec in specs {
        let mapping = SecretMapping::parse(spec)?;
        if !seen_targets.insert(mapping.target_env.clone()) {
            return Err(format!(
                "Duplicate target environment variable '{}' specified",
                mapping.target_env
            ));
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}

pub fn save_vault_keys_unlocked(path: &std::path::Path, keys: &BTreeSet<String>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(keys)
        .map_err(|e| format!("Failed to serialize vault keys: {}", e))?;
    crate::lock::atomic_write_and_rename(path, json.as_bytes())
}

pub fn modify_vault_keys<F, R>(op: F) -> Result<R, String>
where
    F: FnOnce(&mut BTreeSet<String>) -> Result<R, String>,
{
    let path = get_vault_keys_file_path().ok_or("Failed to determine vault keys file path")?;
    let lock_path = get_vault_keys_lock_path().ok_or("Failed to determine vault keys lock path")?;
    let _lock = crate::lock::FileLock::acquire(&lock_path)?;
    let mut keys = list_keys_unlocked(&path);
    let res = op(&mut keys)?;
    save_vault_keys_unlocked(&path, &keys)?;
    Ok(res)
}

pub fn register_key(key: &str) {
    if key.starts_with("__") {
        return;
    }
    let _ = modify_vault_keys(|keys| {
        keys.insert(key.to_string());
        Ok(())
    });
}

pub fn unregister_key(key: &str) {
    let _ = modify_vault_keys(|keys| {
        keys.remove(key);
        Ok(())
    });
}

pub fn set_secret(key: &str, value: &str) -> Result<(), keyring::Error> {
    if !key.starts_with("__") {
        if let Err(msg) = validate_key_name(key) {
            return Err(keyring::Error::Invalid(key.to_string(), msg));
        }
    }
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.set_password(value)?;
    register_key(key);
    Ok(())
}

pub fn get_secret(key: &str) -> Result<String, keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.get_password()
}

pub fn delete_secret(key: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.delete_credential()?;
    unregister_key(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_roundtrip() {
        let key = format!("MY_APP_VALID_KEY_{}", std::process::id());
        let val = "test_val_12345";
        match set_secret(&key, val) {
            Ok(_) => {
                let res_get = get_secret(&key);
                assert_eq!(res_get.unwrap(), val);

                let res_del = delete_secret(&key);
                assert!(res_del.is_ok());
            }
            Err(e) => {
                eprintln!(
                    "[vault_test] Secure storage not available in this environment ({:?}), skipping.",
                    e
                );
            }
        }
    }

    #[test]
    fn test_validate_key_name_rules() {
        assert!(validate_key_name("GITHUB_TOKEN").is_ok());
        assert!(validate_key_name("MY_SECRET_123").is_ok());
        assert!(validate_key_name("_CUSTOM_KEY").is_ok());

        // Reserved prefix
        assert!(validate_key_name("MCP_SENTINEL_CHILD_CONTEXT").is_err());
        assert!(validate_key_name("mcp_sentinel_fake").is_err());
        assert!(validate_key_name("__INTERNAL_KEY").is_err());

        // Invalid characters
        assert!(validate_key_name("KEY=VALUE").is_err());
        assert!(validate_key_name("KEY-WITH-DASH").is_err());
        assert!(validate_key_name("KEY WITH SPACE").is_err());
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name("1_STARTS_WITH_NUMBER").is_err());
    }

    #[test]
    fn test_secret_mapping_parsing() {
        // Plain key
        let m1 = SecretMapping::parse("GITHUB_TOKEN").unwrap();
        assert_eq!(m1.target_env, "GITHUB_TOKEN");
        assert_eq!(m1.vault_key, "GITHUB_TOKEN");
        assert_eq!(m1.canonical_spec(), "GITHUB_TOKEN");
        assert_eq!(m1.display_label(), "GITHUB_TOKEN");

        // Alias mapping
        let m2 = SecretMapping::parse("API_KEY=OPENAI_PROD_KEY").unwrap();
        assert_eq!(m2.target_env, "API_KEY");
        assert_eq!(m2.vault_key, "OPENAI_PROD_KEY");
        assert_eq!(m2.canonical_spec(), "API_KEY=OPENAI_PROD_KEY");
        assert_eq!(m2.display_label(), "API_KEY (from vault: OPENAI_PROD_KEY)");

        // Same target and vault key via equals
        let m3 = SecretMapping::parse("TOKEN=TOKEN").unwrap();
        assert_eq!(m3.canonical_spec(), "TOKEN");
        assert_eq!(m3.display_label(), "TOKEN");

        // Trimming whitespace
        let m4 = SecretMapping::parse("  DB_URL = PROD_DB_URL  ").unwrap();
        assert_eq!(m4.target_env, "DB_URL");
        assert_eq!(m4.vault_key, "PROD_DB_URL");

        // Errors
        assert!(SecretMapping::parse("").is_err());
        assert!(SecretMapping::parse("=PROD_KEY").is_err());
        assert!(SecretMapping::parse("TARGET_ENV=").is_err());
        assert!(SecretMapping::parse("INVALID-KEY=VALID_KEY").is_err());
        assert!(SecretMapping::parse("VALID_KEY=INVALID-KEY").is_err());
        assert!(SecretMapping::parse("MCP_SENTINEL_TOKEN=KEY").is_err());
        assert!(SecretMapping::parse("TOKEN=__INTERNAL_KEY").is_err());
    }

    #[test]
    fn test_parse_specs_duplicate_detection() {
        let specs = vec![
            "API_KEY=KEY_1".to_string(),
            "DB_URL=POSTGRES".to_string(),
            "API_KEY=KEY_2".to_string(),
        ];
        let res = parse_specs(&specs);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Duplicate target environment variable 'API_KEY'"));

        // Distinct targets sharing the same vault key is allowed
        let valid_specs = vec![
            "OPENAI_KEY=COMMON_AI_KEY".to_string(),
            "AI_TOKEN=COMMON_AI_KEY".to_string(),
        ];
        let parsed = parse_specs(&valid_specs).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
