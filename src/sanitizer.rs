use std::collections::HashMap;
use std::env;

#[cfg(windows)]
const SAFE_KEYS: &[&str] = &[
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
];

#[cfg(unix)]
const SAFE_KEYS: &[&str] = &[
    "PATH", "HOME", "USER", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM",
];

/// Builds a sanitized environment map containing only safe system variables
/// and explicitly injected secrets.
pub fn build_sanitized_env(secrets_to_inject: &HashMap<String, String>) -> HashMap<String, String> {
    let mut clean_env = HashMap::new();

    for &key in SAFE_KEYS {
        if let Ok(val) = env::var(key) {
            clean_env.insert(key.to_string(), val);
        }
    }

    // Inject approved secrets
    for (k, v) in secrets_to_inject {
        clean_env.insert(k.clone(), v.clone());
    }

    clean_env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitized_env_isolation() {
        let mut secrets = HashMap::new();
        secrets.insert("TEST_SECRET_KEY".to_string(), "secret_val".to_string());

        let env_map = build_sanitized_env(&secrets);
        assert_eq!(
            env_map.get("TEST_SECRET_KEY"),
            Some(&"secret_val".to_string())
        );

        // Ensure arbitrary custom env variable is NOT present unless injected
        assert!(!env_map.contains_key("RANDOM_UNSAFE_HOST_VARIABLE"));
    }

    #[test]
    fn test_sanitized_env_preserves_path() {
        let secrets = HashMap::new();
        let env_map = build_sanitized_env(&secrets);

        // PATH (or Path on Windows) must be preserved for runtime binary execution
        let has_path = env_map.keys().any(|k| k.eq_ignore_ascii_case("PATH"));
        assert!(has_path, "PATH must be preserved in sanitized environment");
    }

    #[test]
    fn test_multiple_secrets_injection() {
        let mut secrets = HashMap::new();
        secrets.insert("SECRET_1".to_string(), "val_1".to_string());
        secrets.insert("SECRET_2".to_string(), "val_2".to_string());

        let env_map = build_sanitized_env(&secrets);
        assert_eq!(env_map.get("SECRET_1"), Some(&"val_1".to_string()));
        assert_eq!(env_map.get("SECRET_2"), Some(&"val_2".to_string()));
    }
}
