use chrono::{DateTime, Utc};
use directories::BaseDirs;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const MASTER_SIGNING_KEY_NAME: &str = "__MASTER_POLICY_SIGNING_KEY__";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub command: String,
    pub granted_secrets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PolicyFile {
    pub grants: HashMap<String, Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

static MASTER_KEY_CACHE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

pub fn get_config_dir() -> Result<PathBuf, String> {
    if let Ok(custom) = std::env::var("MCP_SENTINEL_CONFIG_DIR") {
        let dir = PathBuf::from(custom);
        let _ = fs::create_dir_all(&dir);
        return Ok(dir);
    }
    let base_dirs = BaseDirs::new().ok_or("Failed to determine system home/config directory")?;
    let config_dir = base_dirs.config_dir().join("mcp-sentinel");
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).map_err(|e| {
            format!(
                "Failed to create config dir {}: {}",
                config_dir.display(),
                e
            )
        })?;

        // Layer 1: Restrict directory permissions to 0700 on Unix (owner access only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(config_dir)
}

fn get_master_key_file_path() -> Option<PathBuf> {
    let config_dir = get_config_dir().ok()?;
    Some(config_dir.join(".master_key"))
}

/// Retrieves or securely generates a 256-bit signing key inside the OS Keyring,
/// with a protected fallback for headless / CI environments without a keyring daemon.
pub fn get_or_create_master_key() -> Result<Vec<u8>, String> {
    #[cfg(any(test, debug_assertions))]
    let mock_keyring_unavailable = std::env::var("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE").is_ok();
    #[cfg(not(any(test, debug_assertions)))]
    let mock_keyring_unavailable = false;

    if !mock_keyring_unavailable {
        if let Some(key) = MASTER_KEY_CACHE.get() {
            return Ok(key.clone());
        }

        // 1. Try retrieving from OS Keyring first (Primary secure hardware/OS enclave)
        if let Ok(hex_str) = crate::vault::get_secret(MASTER_SIGNING_KEY_NAME) {
            if let Ok(bytes) = hex::decode(&hex_str) {
                let _ = MASTER_KEY_CACHE.set(bytes.clone());
                return Ok(bytes);
            }
        }
    }

    // 2. Check if local fallback file exists (for headless/container environments without an OS keyring)
    let allow_file = std::env::var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if allow_file {
        if let Some(key_path) = get_master_key_file_path() {
            if key_path.exists() {
                if let Ok(hex_str) = fs::read_to_string(&key_path) {
                    if let Ok(bytes) = hex::decode(hex_str.trim()) {
                        let _ = MASTER_KEY_CACHE.set(bytes.clone());
                        return Ok(bytes);
                    }
                }
            }
        }
    }

    // 3. Generate a new cryptographically secure 256-bit key
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    let hex_key = hex::encode(key_bytes);

    // Save to OS Keyring as the primary enclave
    let keyring_saved = if mock_keyring_unavailable {
        false
    } else {
        crate::vault::set_secret(MASTER_SIGNING_KEY_NAME, &hex_key).is_ok()
    };

    // Only write to local file if disk keyfile fallback is explicitly permitted
    let mut file_saved = false;
    if allow_file {
        if let Some(key_path) = get_master_key_file_path() {
            if fs::write(&key_path, &hex_key).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                }
                file_saved = true;
            }
        }
    }

    if !keyring_saved && !file_saved {
        return Err(
            "OS Keyring is unavailable and disk keyfile fallback is disabled. \
            Cannot securely persist master signing key. In headless environments, \
            set MCP_SENTINEL_ALLOW_INSECURE_KEYFILE=1 to enable disk keyfile fallback."
                .to_string(),
        );
    }

    let key = key_bytes.to_vec();
    let _ = MASTER_KEY_CACHE.set(key.clone());
    Ok(key)
}

/// Computes a deterministic HMAC-SHA256 signature for all granted permissions.
pub fn compute_grants_hmac(grants: &HashMap<String, Grant>, key: &[u8]) -> String {
    let mut sorted_grants: Vec<(&String, &Grant)> = grants.iter().collect();
    sorted_grants.sort_by_key(|&(k, _)| k);

    let serialized = serde_json::to_vec(&sorted_grants).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can accept key of any length");
    mac.update(&serialized);
    hex::encode(mac.finalize().into_bytes())
}

pub fn get_policy_file_path() -> Result<PathBuf, String> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("permissions.json"))
}

pub fn get_policy_lock_path() -> Result<PathBuf, String> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("permissions.json.lock"))
}

pub fn compute_fingerprint(cmd: &[String]) -> String {
    compute_fingerprint_with_profile(cmd, None)
}

pub fn compute_fingerprint_with_profile(cmd: &[String], profile: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    for arg in cmd {
        hasher.update(arg.as_bytes());
        hasher.update(b"\0"); // Null-byte separator avoids delimiter collisions
    }
    if let Some(prof) = profile {
        hasher.update(b"profile:");
        hasher.update(prof.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

pub fn load_policy() -> PolicyFile {
    let path = match get_policy_file_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[mcp-sentinel] Warning: {}", e);
            return PolicyFile::default();
        }
    };

    if !path.exists() {
        return PolicyFile::default();
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[mcp-sentinel] Warning: failed to read policy file: {}", e);
            return PolicyFile::default();
        }
    };

    let parsed: PolicyFile = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[mcp-sentinel] Warning: corrupted policy file ({}). Discarding.",
                e
            );
            return PolicyFile::default();
        }
    };

    if parsed.grants.is_empty() {
        return parsed;
    }

    // Layer 2: Verify HMAC-SHA256 digital signature against file tampering
    match get_or_create_master_key() {
        Ok(key) => {
            let expected_sig = compute_grants_hmac(&parsed.grants, &key);
            if parsed.signature.as_deref() != Some(&expected_sig) {
                eprintln!(
                    "[mcp-sentinel] SECURITY ALERT: Policy file '{}' has been modified externally or tampered with! Signature mismatch. Discarding untrusted grants.",
                    path.display()
                );
                return PolicyFile::default();
            }
        }
        Err(e) => {
            eprintln!(
                "[mcp-sentinel] Security Warning: Master signing key unavailable ({}). Discarding unverified policy.",
                e
            );
            return PolicyFile::default();
        }
    }

    parsed
}

pub fn save_policy_unlocked(policy: &PolicyFile) -> Result<(), String> {
    let path = get_policy_file_path()?;

    let mut signed_policy = policy.clone();
    let key = get_or_create_master_key()?;
    signed_policy.signature = Some(compute_grants_hmac(&policy.grants, &key));

    let json = serde_json::to_string_pretty(&signed_policy)
        .map_err(|e| format!("Failed to serialize policy: {}", e))?;

    crate::lock::atomic_write_and_rename(&path, json.as_bytes())
}

pub fn modify_policy<F, R>(op: F) -> Result<R, String>
where
    F: FnOnce(&mut PolicyFile) -> Result<R, String>,
{
    let lock_path = get_policy_lock_path()?;
    let _lock = crate::lock::FileLock::acquire(&lock_path)?;
    let mut policy = load_policy();
    let result = op(&mut policy)?;
    save_policy_unlocked(&policy)?;
    Ok(result)
}

pub fn save_policy(policy: &PolicyFile) -> Result<(), String> {
    let lock_path = get_policy_lock_path()?;
    let _lock = crate::lock::FileLock::acquire(&lock_path)?;
    save_policy_unlocked(policy)
}

/// Checks whether all requested secrets have already been authorized for this command fingerprint.
pub fn is_authorized(fingerprint: &str, requested_secrets: &[String]) -> bool {
    is_authorized_with_profile(fingerprint, requested_secrets, None)
}

/// Checks whether all requested secrets have already been authorized for this command fingerprint and profile.
pub fn is_authorized_with_profile(
    fingerprint: &str,
    requested_secrets: &[String],
    expected_profile: Option<&str>,
) -> bool {
    if requested_secrets.is_empty() {
        return true;
    }

    let policy = load_policy();
    if let Some(grant) = policy.grants.get(fingerprint) {
        if grant.profile.as_deref() != expected_profile {
            return false;
        }
        let granted_set: HashSet<&String> = grant.granted_secrets.iter().collect();
        requested_secrets.iter().all(|s| granted_set.contains(s))
    } else {
        false
    }
}

/// Records approval for requested secrets under the command fingerprint.
pub fn record_grant(
    fingerprint: &str,
    name: Option<String>,
    cmd: &[String],
    approved_secrets: &[String],
) -> Result<(), String> {
    record_grant_with_profile(fingerprint, name, cmd, approved_secrets, None)
}

/// Records approval for requested secrets under the command fingerprint with an optional profile.
pub fn record_grant_with_profile(
    fingerprint: &str,
    name: Option<String>,
    cmd: &[String],
    approved_secrets: &[String],
    profile: Option<String>,
) -> Result<(), String> {
    modify_policy(|policy| {
        let command_str = cmd.join(" ");

        let entry = policy
            .grants
            .entry(fingerprint.to_string())
            .or_insert_with(|| Grant {
                id: fingerprint.to_string(),
                name,
                command: command_str,
                granted_secrets: Vec::new(),
                profile: profile.clone(),
                created_at: Utc::now(),
            });

        if entry.profile.is_none() && profile.is_some() {
            entry.profile = profile;
        }

        let mut set: HashSet<String> = entry.granted_secrets.drain(..).collect();
        for s in approved_secrets {
            set.insert(s.clone());
        }
        entry.granted_secrets = set.into_iter().collect();
        entry.granted_secrets.sort();

        Ok(())
    })
}

/// Revoke a grant by its ID (fingerprint).
pub fn revoke_grant(id: &str) -> Result<bool, String> {
    modify_policy(|policy| {
        let removed = policy.grants.remove(id).is_some();
        Ok(removed)
    })
}

/// Reset all granted permissions.
pub fn reset_grants() -> Result<(), String> {
    modify_policy(|policy| {
        policy.grants.clear();
        policy.signature = None;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let cmd1 = vec![
            "npx".to_string(),
            "-y".to_string(),
            "@mcp/github".to_string(),
        ];
        let cmd2 = vec![
            "npx".to_string(),
            "-y".to_string(),
            "@mcp/github".to_string(),
        ];
        let cmd3 = vec![
            "npx".to_string(),
            "-y".to_string(),
            "@mcp/postgres".to_string(),
        ];

        let fp1 = compute_fingerprint(&cmd1);
        let fp2 = compute_fingerprint(&cmd2);
        let fp3 = compute_fingerprint(&cmd3);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert_eq!(fp1.len(), 64); // SHA-256 hex string is 64 characters
    }

    #[test]
    fn test_grant_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        let cmd = vec!["node".to_string(), "server.js".to_string()];
        let fp = compute_fingerprint(&cmd);
        let secrets = vec!["TEST_API_KEY".to_string()];

        // Record grant
        let rec = record_grant(&fp, Some("Test Server".to_string()), &cmd, &secrets);
        assert!(rec.is_ok());

        // Check authorized
        assert!(is_authorized(&fp, &secrets));
        // More secrets than granted should return false
        assert!(!is_authorized(
            &fp,
            &["TEST_API_KEY".to_string(), "UNAUTHORIZED".to_string()]
        ));

        // Revoke
        let rev = revoke_grant(&fp);
        assert!(rev.unwrap());
        assert!(!is_authorized(&fp, &secrets));
    }

    #[test]
    fn test_null_byte_collision_resistance() {
        // "foo", "bar" vs "foobar" must have different fingerprints
        let cmd1 = vec!["foo".to_string(), "bar".to_string()];
        let cmd2 = vec!["foobar".to_string()];

        let fp1 = compute_fingerprint(&cmd1);
        let fp2 = compute_fingerprint(&cmd2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_hmac_signature_verification_and_tamper_detection() {
        let key = b"my_super_secret_master_key_1234";
        let mut grants = HashMap::new();
        grants.insert(
            "fp_sample".to_string(),
            Grant {
                id: "fp_sample".to_string(),
                name: Some("Sample".to_string()),
                command: "node index.js".to_string(),
                granted_secrets: vec!["GITHUB_TOKEN".to_string()],
                profile: None,
                created_at: Utc::now(),
            },
        );

        let sig = compute_grants_hmac(&grants, key);
        assert_eq!(sig.len(), 64);

        // Verification with same key matches
        let sig_verify = compute_grants_hmac(&grants, key);
        assert_eq!(sig, sig_verify);

        // Tampering: An attacker modifies granted_secrets
        let mut tampered_grants = grants.clone();
        tampered_grants
            .get_mut("fp_sample")
            .unwrap()
            .granted_secrets
            .push("MALICIOUS_SECRET_KEY".to_string());

        let tampered_sig = compute_grants_hmac(&tampered_grants, key);
        assert_ne!(sig, tampered_sig, "HMAC must detect tampering of grants!");

        // Tampering: An attacker signs with a forged key
        let forged_key = b"attacker_forged_key_000000000000";
        let forged_sig = compute_grants_hmac(&tampered_grants, forged_key);
        assert_ne!(sig, forged_sig, "Forged key signature cannot match!");
    }

    #[test]
    fn test_master_key_fail_closed_when_keyring_unavailable() {
        let _lock = TEST_LOCK.lock().unwrap();
        std::env::set_var("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1");
        std::env::remove_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE");

        let res = get_or_create_master_key();
        assert!(res.is_err());
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("OS Keyring is unavailable and disk keyfile fallback is disabled"));

        // If allow insecure keyfile is set, it succeeds using fallback file in config dir
        let temp_dir = std::env::temp_dir().join(format!("sentinel_test_policy_keyfile_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        std::env::set_var("MCP_SENTINEL_CONFIG_DIR", temp_dir.to_str().unwrap());
        std::env::set_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1");

        let res_fallback = get_or_create_master_key();
        assert!(res_fallback.is_ok());
        let key = res_fallback.unwrap();
        assert_eq!(key.len(), 32);

        // Verify keyfile exists on disk
        let key_file = temp_dir.join(".master_key");
        assert!(key_file.exists());

        // Cleanup
        std::env::remove_var("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE");
        std::env::remove_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE");
        std::env::remove_var("MCP_SENTINEL_CONFIG_DIR");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_fingerprint_with_profile() {
        let cmd = vec!["node".to_string(), "server.js".to_string()];
        let fp_none = compute_fingerprint(&cmd);
        let fp_prof1 = compute_fingerprint_with_profile(&cmd, Some("read-only"));
        let fp_prof2 = compute_fingerprint_with_profile(&cmd, Some("full-access"));

        assert_ne!(fp_none, fp_prof1);
        assert_ne!(fp_prof1, fp_prof2);
        assert_eq!(fp_none, compute_fingerprint_with_profile(&cmd, None));
    }

    #[test]
    fn test_grant_profile_mismatch_denied() {
        let _lock = TEST_LOCK.lock().unwrap();
        let cmd = vec!["node".to_string(), "profile_test.js".to_string()];
        let fp_ro = compute_fingerprint_with_profile(&cmd, Some("read-only"));
        let secrets = vec!["SECRET_A".to_string()];

        // Record grant with read-only profile
        let rec = record_grant_with_profile(
            &fp_ro,
            Some("Profile Server".to_string()),
            &cmd,
            &secrets,
            Some("read-only".to_string()),
        );
        assert!(rec.is_ok());

        // Authorized with same profile
        assert!(is_authorized_with_profile(&fp_ro, &secrets, Some("read-only")));

        // Unauthorized if no profile or different profile requested
        assert!(!is_authorized_with_profile(&fp_ro, &secrets, None));
        assert!(!is_authorized_with_profile(&fp_ro, &secrets, Some("admin")));

        // Revoke
        let _ = revoke_grant(&fp_ro);
    }
}
