use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const DIALOG_TIMEOUT_SECS: u64 = 30;

/// Sanitizes and truncates a string for safe display inside a native dialog,
/// preventing UI spoofing, line-break overflow, or misleading truncation attacks.
pub fn sanitize_dialog_text(text: &str, max_len: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_control() || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect();

    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    if collapsed.len() > max_len {
        let limit = max_len.saturating_sub(3);
        let boundary = collapsed
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|&idx| idx <= limit)
            .last()
            .unwrap_or(0);
        format!("{}...", &collapsed[..boundary])
    } else {
        collapsed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    AllowAlways,
    AllowOnce,
    Deny,
}

/// Checks whether the current process is running inside a remote SSH session.
pub fn is_ssh_session() -> bool {
    std::env::var("SSH_CONNECTION").is_ok()
        || std::env::var("SSH_CLIENT").is_ok()
        || std::env::var("SSH_TTY").is_ok()
}

/// Displays a native OS dialog asking the user whether to grant access to secrets.
/// Offers three options:
/// - [Allow Always]: Grants access and records permission in permissions.json for future runs.
/// - [Allow Once]: Grants access for this execution only (ephemeral; does not save to disk).
/// - [Deny]: Rejects access and terminates the process.
///
/// Includes a 30-second timeout to prevent locking host IDEs/clients indefinitely.
pub fn ask_user_permission(
    full_cmd: &[String],
    server_name: Option<&str>,
    secrets: &[String],
) -> AuthDecision {
    // Check mock test variable first if present (only in test or debug builds)
    #[cfg(any(test, debug_assertions))]
    if let Ok(mock) = std::env::var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE") {
        let mock_lower = mock.trim().to_lowercase();
        if mock_lower == "allow_once" || mock_lower == "once" {
            return AuthDecision::AllowOnce;
        } else if mock_lower == "allow_always"
            || mock_lower == "always"
            || mock_lower == "allow"
            || mock_lower == "1"
        {
            return AuthDecision::AllowAlways;
        } else if mock_lower == "deny" || mock_lower == "0" {
            return AuthDecision::Deny;
        }
    }

    // In headless / CI environments or when non-interactive, GUI prompt cannot be answered.
    // Immediately return Deny to prevent CI runner hanging.
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("MCP_SENTINEL_NON_INTERACTIVE").is_ok()
        || std::env::var("MCP_SENTINEL_TEST_MODE").is_ok()
    {
        eprintln!(
            "[mcp-sentinel] Non-interactive / CI environment detected. Cannot display interactive consent dialog. Denying access.\n\
             Tip: Pre-authorize on headless/CI using: mcp-sentinel permissions grant [--name <NAME>] --secrets <SECRETS> -- <COMMAND>"
        );
        return AuthDecision::Deny;
    }

    // Remote SSH session check:
    // SSH sessions typically cannot display a GUI prompt (on Windows/macOS or headless Linux).
    // Immediately return Deny instead of hanging for 30s timeout.
    if is_ssh_session() {
        #[cfg(target_os = "linux")]
        let has_display = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
        #[cfg(not(target_os = "linux"))]
        let has_display = false;

        if !has_display {
            eprintln!(
                "[mcp-sentinel] Remote SSH session detected without GUI display. Cannot display interactive consent dialog. Denying access.\n\
                 Tip: Pre-authorize on headless/SSH using: mcp-sentinel permissions grant [--name <NAME>] --secrets <SECRETS> -- <COMMAND>"
            );
            return AuthDecision::Deny;
        }
    }

    #[cfg(target_os = "linux")]
    if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
        eprintln!(
            "[mcp-sentinel] Headless Linux environment detected (neither DISPLAY nor WAYLAND_DISPLAY is set). Cannot display dialog. Denying access.\n\
             Tip: Pre-authorize on headless/SSH using: mcp-sentinel permissions grant [--name <NAME>] --secrets <SECRETS> -- <COMMAND>"
        );
        return AuthDecision::Deny;
    }

    let binary = full_cmd.first().map(|s| s.as_str()).unwrap_or("<unknown>");
    let safe_binary = sanitize_dialog_text(binary, 60);
    let raw_full_cmd = full_cmd.join(" ");
    let safe_full_cmd = sanitize_dialog_text(&raw_full_cmd, 150);
    let raw_secrets = secrets.join(", ");
    let safe_secrets = sanitize_dialog_text(&raw_secrets, 240);

    let server_line = if let Some(name) = server_name {
        format!("Server: {}\n", sanitize_dialog_text(name, 60))
    } else {
        String::new()
    };

    #[cfg(windows)]
    let message = format!(
        "MCP Server is requesting access to environment secrets:\n\n\
        {}Binary: {}\n\
        Full Command: {}\n\
        Requested Secrets: [{}]\n\n\
        Do you authorize this MCP server to access these secrets?\n\
        - [Yes]    -> Allow Always (Save permission for future sessions)\n\
        - [No]     -> Allow Once   (Authorize this run only, do not save)\n\
        - [Cancel] -> Deny         (Reject access and terminate)",
        server_line, safe_binary, safe_full_cmd, safe_secrets
    );

    #[cfg(not(windows))]
    let message = format!(
        "MCP Server is requesting access to environment secrets:\n\n\
        {}Binary: {}\n\
        Full Command: {}\n\
        Requested Secrets: [{}]\n\n\
        Do you authorize this MCP server to access these secrets?\n\
        - [Allow Always]: Authorize and remember for future sessions\n\
        - [Allow Once]: Authorize for this run only (do not remember)\n\
        - [Deny]: Reject access and terminate",
        server_line, safe_binary, safe_full_cmd, safe_secrets
    );

    let (tx, rx) = mpsc::channel();

    let title = "MCP-Sentinel Security Authorization".to_string();
    let btn_always = "Allow Always".to_string();
    let btn_once = "Allow Once".to_string();
    let btn_deny = "Deny".to_string();

    thread::spawn(move || {
        let result = MessageDialog::new()
            .set_title(&title)
            .set_description(&message)
            .set_level(MessageLevel::Warning)
            .set_buttons(MessageButtons::YesNoCancelCustom(
                btn_always, btn_once, btn_deny,
            ))
            .show();

        let decision = match result {
            MessageDialogResult::Custom(ref text) if text == "Allow Always" => {
                AuthDecision::AllowAlways
            }
            MessageDialogResult::Custom(ref text) if text == "Allow Once" => {
                AuthDecision::AllowOnce
            }
            MessageDialogResult::Custom(ref text) if text == "Deny" => AuthDecision::Deny,
            // Fallback for Windows standard MessageBox buttons:
            // [Yes] maps to Allow Always
            // [No] maps to Allow Once
            // [Cancel] / [Close 'X'] maps to Deny
            MessageDialogResult::Yes => AuthDecision::AllowAlways,
            MessageDialogResult::No => AuthDecision::AllowOnce,
            MessageDialogResult::Cancel => AuthDecision::Deny,
            MessageDialogResult::Ok => AuthDecision::AllowAlways,
            _ => AuthDecision::Deny,
        };
        let _ = tx.send(decision);
    });

    match rx.recv_timeout(Duration::from_secs(DIALOG_TIMEOUT_SECS)) {
        Ok(decision) => decision,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "[mcp-sentinel] Security Prompt timed out after {} seconds. Access denied.",
                DIALOG_TIMEOUT_SECS
            );
            AuthDecision::Deny
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!(
                "[mcp-sentinel] Security Prompt dialog was closed or failed to render. Access denied."
            );
            AuthDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static DIALOG_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_sanitize_dialog_text_collapses_newlines() {
        let input = "npx safe-app\n\n\n\n\r\n\t--malicious-flag";
        let output = sanitize_dialog_text(input, 120);
        assert_eq!(output, "npx safe-app --malicious-flag");
    }

    #[test]
    fn test_sanitize_dialog_text_truncates_long_input() {
        let long_input = "a".repeat(200);
        let output = sanitize_dialog_text(&long_input, 50);
        assert_eq!(output.len(), 50);
        assert!(output.ends_with("..."));
    }

    #[test]
    fn test_mock_dialog_response() {
        let _guard = DIALOG_TEST_LOCK.lock().unwrap();
        let dummy_cmd = vec!["dummy_cmd".to_string(), "--arg".to_string()];
        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once");
        let decision = ask_user_permission(&dummy_cmd, Some("test_server"), &["KEY1".to_string()]);
        assert_eq!(decision, AuthDecision::AllowOnce);

        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_always");
        let decision = ask_user_permission(&dummy_cmd, None, &["KEY1".to_string()]);
        assert_eq!(decision, AuthDecision::AllowAlways);

        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "deny");
        let decision = ask_user_permission(&dummy_cmd, Some("test_server"), &["KEY1".to_string()]);
        assert_eq!(decision, AuthDecision::Deny);

        std::env::remove_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE");
    }

    #[test]
    fn test_sanitize_dialog_text_multibyte_utf8() {
        // Vietnamese characters with multi-byte accents
        let input = "Thư mục bí mật chứa nhiều tài liệu quan trọng và khóa bí mật";
        // Ensure no panic when max_len cuts in the middle of a 2-3 byte UTF-8 char
        for len in 5..=60 {
            let res = sanitize_dialog_text(input, len);
            assert!(res.ends_with("...") || res == input);
        }
    }

    #[test]
    fn test_ask_user_permission_with_long_command() {
        let _guard = DIALOG_TEST_LOCK.lock().unwrap();
        let long_args: Vec<String> = (0..50).map(|i| format!("--argument-{}", i)).collect();
        let mut cmd = vec!["npx".to_string()];
        cmd.extend(long_args);

        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once");
        let decision = ask_user_permission(&cmd, Some("my_server"), &["SECRET_1".to_string()]);
        assert_eq!(decision, AuthDecision::AllowOnce);
        std::env::remove_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE");
    }

    #[test]
    fn test_is_ssh_session_detection() {
        let _guard = DIALOG_TEST_LOCK.lock().unwrap();
        std::env::remove_var("SSH_CONNECTION");
        std::env::remove_var("SSH_CLIENT");
        std::env::remove_var("SSH_TTY");
        assert!(!is_ssh_session());

        std::env::set_var("SSH_CONNECTION", "192.168.1.50 51234 192.168.1.1 22");
        assert!(is_ssh_session());
        std::env::remove_var("SSH_CONNECTION");

        std::env::set_var("SSH_CLIENT", "192.168.1.50 51234 22");
        assert!(is_ssh_session());
        std::env::remove_var("SSH_CLIENT");

        std::env::set_var("SSH_TTY", "/dev/pts/1");
        assert!(is_ssh_session());
        std::env::remove_var("SSH_TTY");
    }

    #[test]
    fn test_ssh_session_denies_immediately_without_hanging() {
        let _guard = DIALOG_TEST_LOCK.lock().unwrap();
        let cmd = vec!["node".to_string(), "server.js".to_string()];
        std::env::remove_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE");
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");
        std::env::remove_var("MCP_SENTINEL_NON_INTERACTIVE");
        std::env::remove_var("MCP_SENTINEL_TEST_MODE");

        std::env::set_var("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22");

        let start = std::time::Instant::now();
        let decision = ask_user_permission(&cmd, Some("ssh_server"), &["SECRET_SSH".to_string()]);
        let elapsed = start.elapsed();

        std::env::remove_var("SSH_CONNECTION");

        assert_eq!(decision, AuthDecision::Deny);
        assert!(
            elapsed < Duration::from_secs(3),
            "SSH prompt must return immediately without waiting for 30s timeout! Elapsed: {:?}",
            elapsed
        );
    }
}
