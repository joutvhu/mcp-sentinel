use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::policy::get_config_dir;

pub const AUDIT_LOG_FILE_NAME: &str = "audit.log";
pub const AUDIT_LOCK_FILE_NAME: &str = ".audit.lock";
pub const MAX_AUDIT_LOG_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    ServerStart,
    ServerExit,
    ToolCallAllowed,
    ToolCallBlocked,
    TofuDecision,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::ServerStart => write!(f, "SERVER_START"),
            AuditEventType::ServerExit => write!(f, "SERVER_EXIT"),
            AuditEventType::ToolCallAllowed => write!(f, "TOOL_ALLOWED"),
            AuditEventType::ToolCallBlocked => write!(f, "TOOL_BLOCKED"),
            AuditEventType::TofuDecision => write!(f, "TOFU_DECISION"),
        }
    }
}

impl std::str::FromStr for AuditEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SERVER_START" | "START" => Ok(AuditEventType::ServerStart),
            "SERVER_EXIT" | "EXIT" => Ok(AuditEventType::ServerExit),
            "TOOL_ALLOWED" | "ALLOWED" => Ok(AuditEventType::ToolCallAllowed),
            "TOOL_BLOCKED" | "BLOCKED" => Ok(AuditEventType::ToolCallBlocked),
            "TOFU_DECISION" | "TOFU" => Ok(AuditEventType::TofuDecision),
            other => Err(format!("Unknown audit event type: '{}'", other)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event: AuditEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct AuditStatus {
    pub enabled_by_default: bool,
    pub is_env_enabled: bool,
    pub log_path: PathBuf,
    pub log_exists: bool,
    pub file_size_bytes: u64,
    pub total_entries: usize,
}

/// Resolves the filesystem path to `audit.log`.
pub fn get_audit_log_path() -> Result<PathBuf, String> {
    let dir = get_config_dir()?;
    Ok(dir.join(AUDIT_LOG_FILE_NAME))
}

/// Resolves the filesystem path to `.audit.lock`.
pub fn get_audit_lock_path() -> Result<PathBuf, String> {
    let dir = get_config_dir()?;
    Ok(dir.join(AUDIT_LOCK_FILE_NAME))
}

/// Determines whether auditing is active based on the CLI `--audit` flag and `MCP_SENTINEL_AUDIT` env var.
/// Default is strictly `false` (Disabled by default).
pub fn is_audit_enabled(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    match std::env::var("MCP_SENTINEL_AUDIT") {
        Ok(v) => {
            let val = v.trim();
            val == "1" || val.eq_ignore_ascii_case("true") || val.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

/// Rotates `audit.log` to `audit.log.1` if it exceeds the maximum size limit (5 MB).
fn rotate_if_needed(path: &PathBuf) -> Result<(), String> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() >= MAX_AUDIT_LOG_SIZE {
            let backup_path = path.with_extension("log.1");
            if backup_path.exists() {
                let _ = fs::remove_file(&backup_path);
            }
            if let Err(_e) = fs::rename(path, &backup_path) {
                // Safe fallback for Windows sharing violations or cross-device links:
                // Attempt copy and truncate; if even that fails, ignore so proxy flow is not blocked.
                if fs::copy(path, &backup_path).is_ok() {
                    let _ = OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(path);
                }
            }
        }
    }
    Ok(())
}

/// Appends an `AuditEntry` to `audit.log` as a single-line JSON string.
pub fn log_event(entry: &AuditEntry) -> Result<(), String> {
    let lock_path = get_audit_lock_path()?;
    let _lock = crate::lock::FileLock::acquire(&lock_path)?;

    let log_path = get_audit_log_path()?;
    rotate_if_needed(&log_path)?;

    let json_line = serde_json::to_string(entry)
        .map_err(|e| format!("Failed to serialize audit entry: {}", e))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("Failed to open audit log {}: {}", log_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
    }

    writeln!(file, "{}", json_line).map_err(|e| format!("Failed to write to audit log: {}", e))?;

    Ok(())
}

/// Reads recorded audit events from disk, applying optional filters.
pub fn read_entries(
    limit: usize,
    event_filter: Option<AuditEventType>,
    blocked_only: bool,
) -> Result<Vec<AuditEntry>, String> {
    let log_path = get_audit_log_path()?;
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&log_path)
        .map_err(|e| format!("Failed to open audit log {}: {}", log_path.display(), e))?;

    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            if blocked_only && entry.event != AuditEventType::ToolCallBlocked {
                continue;
            }
            if let Some(ref filter) = event_filter {
                if &entry.event != filter {
                    continue;
                }
            }
            entries.push(entry);
        }
    }

    // Return the latest entries up to limit
    if entries.len() > limit {
        let start = entries.len() - limit;
        Ok(entries[start..].to_vec())
    } else {
        Ok(entries)
    }
}

/// Purges all entries from `audit.log`.
pub fn clear_log() -> Result<bool, String> {
    let lock_path = get_audit_lock_path()?;
    let _lock = crate::lock::FileLock::acquire(&lock_path)?;

    let log_path = get_audit_log_path()?;
    let mut removed = false;
    if log_path.exists() {
        fs::remove_file(&log_path)
            .map_err(|e| format!("Failed to remove {}: {}", log_path.display(), e))?;
        removed = true;
    }
    let backup_path = log_path.with_extension("log.1");
    if backup_path.exists() {
        let _ = fs::remove_file(&backup_path);
        removed = true;
    }
    Ok(removed)
}

/// Retrieves the current status and metrics of the audit logging subsystem.
pub fn get_audit_status() -> Result<AuditStatus, String> {
    let log_path = get_audit_log_path()?;
    let is_env_enabled = is_audit_enabled(false);

    let (log_exists, file_size_bytes, total_entries) = if log_path.exists() {
        let meta = fs::metadata(&log_path).ok();
        let size = meta.map(|m| m.len()).unwrap_or(0);

        let count = if let Ok(file) = fs::File::open(&log_path) {
            BufReader::new(file).lines().count()
        } else {
            0
        };

        (true, size, count)
    } else {
        (false, 0, 0)
    };

    Ok(AuditStatus {
        enabled_by_default: false,
        is_env_enabled,
        log_path,
        log_exists,
        file_size_bytes,
        total_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_audit_enabled_logic() {
        // Explicit cli flag true -> true
        assert!(is_audit_enabled(true));

        // When flag is false, depends on env
        std::env::remove_var("MCP_SENTINEL_AUDIT");
        assert!(!is_audit_enabled(false));

        std::env::set_var("MCP_SENTINEL_AUDIT", "1");
        assert!(is_audit_enabled(false));

        std::env::set_var("MCP_SENTINEL_AUDIT", "true");
        assert!(is_audit_enabled(false));

        std::env::set_var("MCP_SENTINEL_AUDIT", "0");
        assert!(!is_audit_enabled(false));

        std::env::remove_var("MCP_SENTINEL_AUDIT");
    }

    #[test]
    fn test_audit_event_type_display_and_parse() {
        let evt = AuditEventType::ToolCallBlocked;
        assert_eq!(evt.to_string(), "TOOL_BLOCKED");

        let parsed: AuditEventType = "TOOL_BLOCKED".parse().unwrap();
        assert_eq!(parsed, AuditEventType::ToolCallBlocked);

        let parsed_start: AuditEventType = "SERVER_START".parse().unwrap();
        assert_eq!(parsed_start, AuditEventType::ServerStart);
    }

    #[test]
    fn test_audit_entry_serialization_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event: AuditEventType::ToolCallBlocked,
            server_name: Some("test-mcp".to_string()),
            command: Some("npx server".to_string()),
            tool_name: Some("drop_table".to_string()),
            decision: Some("BLOCKED".to_string()),
            reason: Some("Matches deny pattern".to_string()),
            secrets: Some(vec!["KEY_A".to_string()]),
            profile: Some("read-only".to_string()),
            exit_code: None,
        };

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.event, AuditEventType::ToolCallBlocked);
        assert_eq!(deserialized.tool_name.as_deref(), Some("drop_table"));
        assert_eq!(deserialized.profile.as_deref(), Some("read-only"));
        assert_eq!(deserialized.secrets.unwrap(), vec!["KEY_A".to_string()]);
    }
}
