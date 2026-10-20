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
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "VIRTUAL_ENV",
    "HOMEDRIVE",
    "HOMEPATH",
    "ALLUSERSPROFILE",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
];

#[cfg(unix)]
const SAFE_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TERM",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "VIRTUAL_ENV",
];

static CURRENT_EXE_DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();

fn get_current_exe_dir() -> Option<&'static std::path::Path> {
    CURRENT_EXE_DIR
        .get_or_init(|| env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())))
        .as_deref()
}

/// Sanitizes a PATH-like environment string by removing occurrences of `exe_dir`.
pub fn sanitize_path(path_val: &str, exe_dir: &std::path::Path) -> std::ffi::OsString {
    let exe_str = exe_dir.to_string_lossy();
    #[cfg(windows)]
    let exe_norm = exe_str.trim_end_matches(['\\', '/']);
    #[cfg(not(windows))]
    let exe_norm = exe_str.trim_end_matches('/');

    let filtered_paths: Vec<_> = env::split_paths(path_val)
        .filter(|p| {
            let p_str = p.to_string_lossy();
            #[cfg(windows)]
            {
                let p_norm = p_str.trim_end_matches(['\\', '/']);
                !p_norm.eq_ignore_ascii_case(exe_norm)
            }
            #[cfg(not(windows))]
            {
                let p_norm = p_str.trim_end_matches('/');
                p_norm != exe_norm
            }
        })
        .collect();
    env::join_paths(filtered_paths).unwrap_or_default()
}

/// Builds a sanitized environment map containing only safe system variables
/// and explicitly injected secrets. Injects a child security context lock to prevent recursion.
pub fn build_sanitized_env(secrets_to_inject: &HashMap<String, String>) -> HashMap<String, String> {
    let mut clean_env = HashMap::new();

    for &key in SAFE_KEYS {
        if let Ok(val) = env::var(key) {
            clean_env.insert(key.to_string(), val);
        }
    }

    // Strip mcp-sentinel executable directory from PATH to prevent direct execution by child processes
    if let Some(exe_dir) = get_current_exe_dir() {
        let path_key = clean_env
            .keys()
            .find(|k| k.eq_ignore_ascii_case("PATH"))
            .cloned();
        if let Some(key) = path_key {
            if let Some(path_val) = clean_env.get(&key) {
                let new_path = sanitize_path(path_val, exe_dir);
                if let Some(s) = new_path.to_str() {
                    clean_env.insert(key, s.to_string());
                }
            }
        }
    }

    // Inject approved secrets (excluding reserved sentinel prefixes)
    for (k, v) in secrets_to_inject {
        if !k.to_uppercase().starts_with("MCP_SENTINEL") && !k.starts_with("__") {
            clean_env.insert(k.clone(), v.clone());
        }
    }

    // Inject child security context flag LAST so it cannot be overridden
    clean_env.insert("MCP_SENTINEL_CHILD_CONTEXT".to_string(), "1".to_string());

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

    #[test]
    fn test_sanitized_env_child_security_context() {
        let secrets = HashMap::new();
        let env_map = build_sanitized_env(&secrets);
        assert_eq!(
            env_map.get("MCP_SENTINEL_CHILD_CONTEXT"),
            Some(&"1".to_string()),
            "Child environment must always contain child security context lock"
        );
    }

    #[test]
    fn test_sanitized_env_cannot_override_reserved_flags() {
        let mut malicious_secrets = HashMap::new();
        malicious_secrets.insert("MCP_SENTINEL_CHILD_CONTEXT".to_string(), "0".to_string());
        malicious_secrets.insert("mcp_sentinel_custom".to_string(), "evil".to_string());
        malicious_secrets.insert("__INTERNAL_KEY".to_string(), "bad".to_string());

        let env_map = build_sanitized_env(&malicious_secrets);
        assert_eq!(
            env_map.get("MCP_SENTINEL_CHILD_CONTEXT"),
            Some(&"1".to_string()),
            "Child security context must remain 1 despite malicious override attempt"
        );
        assert!(!env_map.contains_key("mcp_sentinel_custom"));
        assert!(!env_map.contains_key("__INTERNAL_KEY"));
    }

    #[test]
    fn test_sanitize_path_removes_exe_dir() {
        let temp_dir = std::env::temp_dir();
        let dir_a = temp_dir.join("test_sentinel_dir_a");
        let dir_b = temp_dir.join("test_sentinel_dir_b");
        let dir_c = temp_dir.join("test_sentinel_dir_c");

        let combined = env::join_paths(vec![&dir_a, &dir_b, &dir_c]).unwrap();
        let cleaned = sanitize_path(combined.to_str().unwrap(), &dir_b);
        let split_cleaned: Vec<_> = env::split_paths(&cleaned).collect();

        assert_eq!(split_cleaned.len(), 2);
        assert!(!split_cleaned.iter().any(|p| p == &dir_b));
        assert!(split_cleaned.iter().any(|p| p == &dir_a));
        assert!(split_cleaned.iter().any(|p| p == &dir_c));
    }
}
