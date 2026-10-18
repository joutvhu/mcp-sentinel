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

/// Displays a native OS dialog asking the user whether to grant access to secrets.
/// Offers three options:
/// - [Allow Always]: Grants access and records permission in permissions.json for future runs.
/// - [Allow Once]: Grants access for this execution only (ephemeral; does not save to disk).
/// - [Deny]: Rejects access and terminates the process.
///
/// Includes a 30-second timeout to prevent locking host IDEs/clients indefinitely.
pub fn ask_user_permission(command_name: &str, secrets: &[String]) -> AuthDecision {
    // Check mock test variable first if present
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

    let safe_command = sanitize_dialog_text(command_name, 120);
    let raw_secrets = secrets.join(", ");
    let safe_secrets = sanitize_dialog_text(&raw_secrets, 240);

    let message = format!(
        "MCP Server is requesting access to environment secrets:\n\n\
        Command: {}\n\
        Requested Secrets: [{}]\n\n\
        Do you authorize this MCP server to access these secrets?\n\
        - [Allow Always]: Authorize and remember for future sessions\n\
        - [Allow Once]: Authorize for this run only (do not remember)\n\
        - [Deny]: Reject access and terminate",
        safe_command, safe_secrets
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
            MessageDialogResult::Yes => AuthDecision::AllowAlways,
            MessageDialogResult::No => AuthDecision::Deny,
            MessageDialogResult::Ok => AuthDecision::AllowAlways,
            MessageDialogResult::Cancel => AuthDecision::Deny,
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
        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once");
        let decision = ask_user_permission("dummy_cmd", &["KEY1".to_string()]);
        assert_eq!(decision, AuthDecision::AllowOnce);

        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_always");
        let decision = ask_user_permission("dummy_cmd", &["KEY1".to_string()]);
        assert_eq!(decision, AuthDecision::AllowAlways);

        std::env::set_var("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "deny");
        let decision = ask_user_permission("dummy_cmd", &["KEY1".to_string()]);
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
}
