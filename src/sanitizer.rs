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

static CURRENT_EXE_DIR: std::sync::OnceLock<Option<std::path::PathBuf>> =
    std::sync::OnceLock::new();

fn get_current_exe_dir() -> Option<&'static std::path::Path> {
    CURRENT_EXE_DIR
        .get_or_init(|| {
            env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        })
        .as_deref()
}

/// Checks whether a given directory is a shared system/user tool directory
/// (such as ~/.cargo/bin, /opt/homebrew/bin, /usr/local/bin, /usr/bin, System32, npm, shims, etc.)
/// where other runtime tools (node, python, git, etc.) reside.
pub fn is_shared_bin_dir(dir: &std::path::Path) -> bool {
    let s = dir.to_string_lossy().replace('\\', "/").to_lowercase();
    let trimmed = s.trim_end_matches('/');

    trimmed.ends_with("/.cargo/bin")
        || trimmed.ends_with(".cargo/bin")
        || trimmed.ends_with("/opt/homebrew/bin")
        || trimmed.ends_with("opt/homebrew/bin")
        || trimmed.ends_with("/usr/local/bin")
        || trimmed.ends_with("usr/local/bin")
        || trimmed.ends_with("/usr/bin")
        || trimmed == "/bin"
        || trimmed == "bin"
        || trimmed.ends_with("/usr/sbin")
        || trimmed == "/sbin"
        || trimmed == "sbin"
        || trimmed.ends_with("/system32")
        || trimmed.ends_with("/windows")
        || trimmed.ends_with("/npm")
        || trimmed.ends_with("/shims")
        || trimmed.ends_with("/scripts")
        || trimmed.ends_with("/.local/bin")
        || trimmed.ends_with(".local/bin")
}

/// Sanitizes a PATH-like environment string by removing occurrences of `exe_dir`.
/// If `exe_dir` or the path component is a shared tool directory (like ~/.cargo/bin, /opt/homebrew/bin, etc.),
/// it is preserved to avoid stripping access to node, python, git, and other runtime tools.
pub fn sanitize_path(path_val: &str, exe_dir: &std::path::Path) -> std::ffi::OsString {
    if is_shared_bin_dir(exe_dir) {
        return std::ffi::OsString::from(path_val);
    }

    let exe_str = exe_dir.to_string_lossy();
    #[cfg(windows)]
    let exe_norm = exe_str
        .replace('/', "\\")
        .trim_end_matches(['\\', '/'])
        .to_lowercase();
    #[cfg(not(windows))]
    let exe_norm = exe_str.trim_end_matches('/').to_string();

    let filtered_paths: Vec<_> = env::split_paths(path_val)
        .filter(|p| {
            if is_shared_bin_dir(p) {
                return true;
            }
            let p_str = p.to_string_lossy();
            #[cfg(windows)]
            {
                let p_norm = p_str
                    .replace('/', "\\")
                    .trim_end_matches(['\\', '/'])
                    .to_lowercase();
                p_norm != exe_norm
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

/// Builds a sanitized environment map containing only safe system variables,
/// explicitly passed environment variables from the host, and injected secrets.
/// Injects a child security context lock to prevent recursion.
pub fn build_sanitized_env(
    secrets_to_inject: &HashMap<String, String>,
    pass_env_keys: &[String],
) -> HashMap<String, String> {
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

    // Pass through explicit host environment variables (excluding dangerous runtime vars and reserved prefixes)
    for raw_key in pass_env_keys {
        let key = raw_key.trim();
        if key.is_empty() {
            continue;
        }
        if key.starts_with("__") || key.to_uppercase().starts_with("MCP_SENTINEL") {
            continue;
        }
        if crate::vault::is_dangerous_runtime_var(key) {
            continue;
        }
        if let Ok(val) = env::var(key) {
            clean_env.insert(key.to_string(), val);
        }
    }

    // Inject approved secrets (excluding reserved sentinel prefixes and dangerous runtime vars)
    for (k, v) in secrets_to_inject {
        if !k.to_uppercase().starts_with("MCP_SENTINEL")
            && !k.starts_with("__")
            && !crate::vault::is_dangerous_runtime_var(k)
        {
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

        let env_map = build_sanitized_env(&secrets, &[]);
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
        let env_map = build_sanitized_env(&secrets, &[]);

        // PATH (or Path on Windows) must be preserved for runtime binary execution
        let has_path = env_map.keys().any(|k| k.eq_ignore_ascii_case("PATH"));
        assert!(has_path, "PATH must be preserved in sanitized environment");
    }

    #[test]
    fn test_multiple_secrets_injection() {
        let mut secrets = HashMap::new();
        secrets.insert("SECRET_1".to_string(), "val_1".to_string());
        secrets.insert("SECRET_2".to_string(), "val_2".to_string());

        let env_map = build_sanitized_env(&secrets, &[]);
        assert_eq!(env_map.get("SECRET_1"), Some(&"val_1".to_string()));
        assert_eq!(env_map.get("SECRET_2"), Some(&"val_2".to_string()));
    }

    #[test]
    fn test_sanitized_env_child_security_context() {
        let secrets = HashMap::new();
        let env_map = build_sanitized_env(&secrets, &[]);
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

        let env_map = build_sanitized_env(&malicious_secrets, &[]);
        assert_eq!(
            env_map.get("MCP_SENTINEL_CHILD_CONTEXT"),
            Some(&"1".to_string()),
            "Child security context must remain 1 despite malicious override attempt"
        );
        assert!(!env_map.contains_key("mcp_sentinel_custom"));
        assert!(!env_map.contains_key("__INTERNAL_KEY"));
    }

    #[test]
    fn test_sanitized_env_pass_env_forwarding() {
        std::env::set_var("TEST_SAFE_CFG_PORT", "8080");
        std::env::set_var("TEST_SAFE_CFG_DB", "postgres://localhost/db");

        let secrets = HashMap::new();
        let pass_keys = vec![
            "TEST_SAFE_CFG_PORT".to_string(),
            "TEST_SAFE_CFG_DB".to_string(),
            "NON_EXISTENT_VAR".to_string(),
        ];

        let env_map = build_sanitized_env(&secrets, &pass_keys);
        assert_eq!(env_map.get("TEST_SAFE_CFG_PORT"), Some(&"8080".to_string()));
        assert_eq!(
            env_map.get("TEST_SAFE_CFG_DB"),
            Some(&"postgres://localhost/db".to_string())
        );
        assert!(!env_map.contains_key("NON_EXISTENT_VAR"));

        std::env::remove_var("TEST_SAFE_CFG_PORT");
        std::env::remove_var("TEST_SAFE_CFG_DB");
    }

    #[test]
    fn test_sanitized_env_pass_env_blocks_dangerous_and_reserved() {
        std::env::set_var("NODE_OPTIONS", "--require evil.js");
        std::env::set_var("PYTHONPATH", "/tmp/evil");
        std::env::set_var("LD_PRELOAD", "/tmp/evil.so");
        std::env::set_var("__SENTINEL_INTERNAL", "bad");
        std::env::set_var("MCP_SENTINEL_CUSTOM", "bad");

        let secrets = HashMap::new();
        let pass_keys = vec![
            "NODE_OPTIONS".to_string(),
            "pythonpath".to_string(),
            "LD_PRELOAD".to_string(),
            "__SENTINEL_INTERNAL".to_string(),
            "MCP_SENTINEL_CUSTOM".to_string(),
        ];

        let env_map = build_sanitized_env(&secrets, &pass_keys);
        assert!(!env_map.contains_key("NODE_OPTIONS"));
        assert!(!env_map.contains_key("pythonpath"));
        assert!(!env_map.contains_key("PYTHONPATH"));
        assert!(!env_map.contains_key("LD_PRELOAD"));
        assert!(!env_map.contains_key("__SENTINEL_INTERNAL"));
        assert!(!env_map.contains_key("MCP_SENTINEL_CUSTOM"));

        std::env::remove_var("NODE_OPTIONS");
        std::env::remove_var("PYTHONPATH");
        std::env::remove_var("LD_PRELOAD");
        std::env::remove_var("__SENTINEL_INTERNAL");
        std::env::remove_var("MCP_SENTINEL_CUSTOM");
    }

    #[test]
    fn test_sanitized_env_secrets_override_pass_env() {
        std::env::set_var("SHARED_KEY", "host_value");

        let mut secrets = HashMap::new();
        secrets.insert("SHARED_KEY".to_string(), "vault_secret_value".to_string());

        let pass_keys = vec!["SHARED_KEY".to_string()];
        let env_map = build_sanitized_env(&secrets, &pass_keys);
        assert_eq!(
            env_map.get("SHARED_KEY"),
            Some(&"vault_secret_value".to_string())
        );

        std::env::remove_var("SHARED_KEY");
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

    #[test]
    fn test_sanitize_path_preserves_shared_bin_dirs() {
        let cargo_bin = std::path::Path::new("/home/user/.cargo/bin");
        let homebrew_bin = std::path::Path::new("/opt/homebrew/bin");
        let usr_local_bin = std::path::Path::new("/usr/local/bin");
        let dedicated_dir = std::path::Path::new("/opt/mcp-sentinel/bin");

        assert!(is_shared_bin_dir(cargo_bin));
        assert!(is_shared_bin_dir(homebrew_bin));
        assert!(is_shared_bin_dir(usr_local_bin));
        assert!(!is_shared_bin_dir(dedicated_dir));

        // When exe_dir is ~/.cargo/bin, sanitize_path must NOT remove it from PATH
        let path_list = vec![cargo_bin, homebrew_bin, usr_local_bin];
        let combined = env::join_paths(&path_list).unwrap();
        let cleaned = sanitize_path(combined.to_str().unwrap(), cargo_bin);
        let split_cleaned: Vec<_> = env::split_paths(&cleaned).collect();

        assert_eq!(split_cleaned.len(), 3);
        assert!(split_cleaned.iter().any(|p| p == cargo_bin));
        assert!(split_cleaned.iter().any(|p| p == homebrew_bin));
        assert!(split_cleaned.iter().any(|p| p == usr_local_bin));

        // Dedicated dir is still removed, but shared dirs in PATH are preserved
        let with_dedicated = vec![cargo_bin, dedicated_dir, usr_local_bin];
        let combined_dedicated = env::join_paths(&with_dedicated).unwrap();
        let cleaned_dedicated = sanitize_path(combined_dedicated.to_str().unwrap(), dedicated_dir);
        let split_dedicated: Vec<_> = env::split_paths(&cleaned_dedicated).collect();

        assert_eq!(split_dedicated.len(), 2);
        assert!(!split_dedicated.iter().any(|p| p == dedicated_dir));
        assert!(split_dedicated.iter().any(|p| p == cargo_bin));
        assert!(split_dedicated.iter().any(|p| p == usr_local_bin));
    }

    #[test]
    #[cfg(windows)]
    fn test_sanitize_path_windows_slash_normalization() {
        let dir_b = std::path::Path::new("C:\\tools\\dedicated_sentinel\\bin");
        let safe_dir = std::path::Path::new("C:\\tools\\other_app\\bin");

        let combined = "C:/tools/dedicated_sentinel/bin;C:\\tools\\other_app\\bin".to_string();
        let cleaned = sanitize_path(&combined, dir_b);
        let split_cleaned: Vec<_> = env::split_paths(&cleaned).collect();

        assert_eq!(split_cleaned.len(), 1);
        assert!(split_cleaned.iter().any(|p| p == safe_dir));
    }
}
