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
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PolicyFile {
    pub grants: HashMap<String, Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

static MASTER_KEY_CACHE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Retrieves or securely generates a 256-bit signing key inside the OS Keyring.
pub fn get_or_create_master_key() -> Result<Vec<u8>, String> {
    if let Some(key) = MASTER_KEY_CACHE.get() {
        return Ok(key.clone());
    }

    let key = match crate::vault::get_secret(MASTER_SIGNING_KEY_NAME) {
        Ok(hex_str) => hex::decode(&hex_str).map_err(|e| e.to_string())?,
        Err(_) => {
            use rand::rngs::OsRng;
            use rand::RngCore;

            let mut key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut key_bytes);

            let hex_key = hex::encode(key_bytes);
            let _ = crate::vault::set_secret(MASTER_SIGNING_KEY_NAME, &hex_key);
            key_bytes.to_vec()
        }
    };

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

        // Lớp 1: Khóa quyền thư mục 0700 trên Unix (chỉ chủ sở hữu truy cập)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(config_dir.join("permissions.json"))
}

pub fn compute_fingerprint(cmd: &[String]) -> String {
    let mut hasher = Sha256::new();
    for arg in cmd {
        hasher.update(arg.as_bytes());
        hasher.update(b"\0"); // Null-byte separator avoids delimiter collisions
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

    // Lớp 2: Xác minh chữ ký số HMAC-SHA256 chống can thiệp file
    if let Ok(key) = get_or_create_master_key() {
        let expected_sig = compute_grants_hmac(&parsed.grants, &key);
        if parsed.signature.as_deref() != Some(&expected_sig) {
            eprintln!(
                "[mcp-sentinel] SECURITY ALERT: Policy file '{}' has been modified externally or tampered with! Signature mismatch. Discarding untrusted grants.",
                path.display()
            );
            return PolicyFile::default();
        }
    }

    parsed
}

pub fn save_policy(policy: &PolicyFile) -> Result<(), String> {
    let path = get_policy_file_path()?;

    let mut signed_policy = policy.clone();
    if let Ok(key) = get_or_create_master_key() {
        signed_policy.signature = Some(compute_grants_hmac(&policy.grants, &key));
    }

    let json = serde_json::to_string_pretty(&signed_policy)
        .map_err(|e| format!("Failed to serialize policy: {}", e))?;
    fs::write(&path, json).map_err(|e| format!("Failed to write policy file: {}", e))?;

    // Lớp 1: Khóa quyền file 0600 trên Unix (chỉ chủ sở hữu đọc/ghi)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Checks whether all requested secrets have already been authorized for this command fingerprint.
pub fn is_authorized(fingerprint: &str, requested_secrets: &[String]) -> bool {
    if requested_secrets.is_empty() {
        return true;
    }

    let policy = load_policy();
    if let Some(grant) = policy.grants.get(fingerprint) {
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
    let mut policy = load_policy();
    let command_str = cmd.join(" ");

    let entry = policy
        .grants
        .entry(fingerprint.to_string())
        .or_insert_with(|| Grant {
            id: fingerprint.to_string(),
            name,
            command: command_str,
            granted_secrets: Vec::new(),
            created_at: Utc::now(),
        });

    let mut set: HashSet<String> = entry.granted_secrets.drain(..).collect();
    for s in approved_secrets {
        set.insert(s.clone());
    }
    entry.granted_secrets = set.into_iter().collect();
    entry.granted_secrets.sort();

    save_policy(&policy)
}

/// Revoke a grant by its ID (fingerprint).
pub fn revoke_grant(id: &str) -> Result<bool, String> {
    let mut policy = load_policy();
    let removed = policy.grants.remove(id).is_some();
    if removed {
        save_policy(&policy)?;
    }
    Ok(removed)
}

/// Reset all granted permissions.
pub fn reset_grants() -> Result<(), String> {
    let policy = PolicyFile::default();
    save_policy(&policy)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
