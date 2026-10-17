use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const DIALOG_TIMEOUT_SECS: u64 = 60;

/// Sanitizes and truncates a string for safe display inside a native dialog,
/// preventing UI spoofing, line-break overflow, or misleading truncation attacks.
pub fn sanitize_dialog_text(text: &str, max_len: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() || c == '\n' || c == '\r' { ' ' } else { c })
        .collect();

    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    if collapsed.len() > max_len {
        format!("{}...", &collapsed[..max_len.saturating_sub(3)])
    } else {
        collapsed
    }
}

/// Displays a native OS dialog asking the user whether to grant access to secrets.
/// Includes a 60-second timeout to prevent locking host IDEs/clients indefinitely.
pub fn ask_user_permission(command_name: &str, secrets: &[String]) -> bool {
    let safe_command = sanitize_dialog_text(command_name, 120);
    let raw_secrets = secrets.join(", ");
    let safe_secrets = sanitize_dialog_text(&raw_secrets, 120);

    let message = format!(
        "MCP Server is requesting access to environment secrets:\n\n\
        Command: {}\n\
        Requested Secrets: [{}]\n\n\
        Do you allow this MCP server to access these secrets?\n\
        (This permission will be remembered for future runs)",
        safe_command, safe_secrets
    );

    let (tx, rx) = mpsc::channel();

    let title = "MCP-Sentinel Security Authorization".to_string();
    thread::spawn(move || {
        let result = MessageDialog::new()
            .set_title(&title)
            .set_description(&message)
            .set_level(MessageLevel::Warning)
            .set_buttons(MessageButtons::OkCancel)
            .show();

        let allowed = result == MessageDialogResult::Ok;
        let _ = tx.send(allowed);
    });

    match rx.recv_timeout(Duration::from_secs(DIALOG_TIMEOUT_SECS)) {
        Ok(allowed) => allowed,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "[mcp-sentinel] Security Prompt timed out after {} seconds. Access denied.",
                DIALOG_TIMEOUT_SECS
            );
            false
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("[mcp-sentinel] Security Prompt dialog was closed or failed to render. Access denied.");
            false
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
}
