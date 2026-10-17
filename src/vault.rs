use directories::BaseDirs;
use keyring::Entry;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub const SERVICE_NAME: &str = "mcp-sentinel";

fn get_vault_keys_file_path() -> Option<PathBuf> {
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

pub fn list_keys() -> Vec<String> {
    if let Some(path) = get_vault_keys_file_path() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(keys) = serde_json::from_str::<BTreeSet<String>>(&content) {
                return keys.into_iter().collect();
            }
        }
    }
    Vec::new()
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
    if key.starts_with("__") || key.to_uppercase().starts_with("MCP_SENTINEL_") {
        return Err(format!(
            "Secret key '{}' uses a reserved prefix ('__' or 'MCP_SENTINEL_')",
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

fn register_key(key: &str) {
    if key.starts_with("__") {
        return;
    }
    if let Some(path) = get_vault_keys_file_path() {
        let mut keys: BTreeSet<String> = list_keys().into_iter().collect();
        keys.insert(key.to_string());
        if let Ok(json) = serde_json::to_string_pretty(&keys) {
            let _ = fs::write(&path, json);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn unregister_key(key: &str) {
    if let Some(path) = get_vault_keys_file_path() {
        let mut keys: BTreeSet<String> = list_keys().into_iter().collect();
        keys.remove(key);
        if let Ok(json) = serde_json::to_string_pretty(&keys) {
            let _ = fs::write(&path, json);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }
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
        let key = "MY_APP_VALID_SECRET_KEY";
        let val = "test_val_12345";
        match set_secret(key, val) {
            Ok(_) => {
                let res_get = get_secret(key);
                assert_eq!(res_get.unwrap(), val);

                let res_del = delete_secret(key);
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
}
