use directories::BaseDirs;
use keyring::Entry;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub const SERVICE_NAME: &str = "mcp-sentinel";

fn get_vault_keys_file_path() -> Option<PathBuf> {
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

fn register_key(key: &str) {
    if key.starts_with("__") {
        return;
    }
    if let Some(path) = get_vault_keys_file_path() {
        let mut keys: BTreeSet<String> = list_keys().into_iter().collect();
        keys.insert(key.to_string());
        if let Ok(json) = serde_json::to_string_pretty(&keys) {
            let _ = fs::write(&path, json);
        }
    }
}

fn unregister_key(key: &str) {
    if let Some(path) = get_vault_keys_file_path() {
        let mut keys: BTreeSet<String> = list_keys().into_iter().collect();
        keys.remove(key);
        if let Ok(json) = serde_json::to_string_pretty(&keys) {
            let _ = fs::write(&path, json);
        }
    }
}

pub fn set_secret(key: &str, value: &str) -> Result<(), keyring::Error> {
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
        let key = "MCP_SENTINEL_UNIT_TEST_KEY";
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
}
