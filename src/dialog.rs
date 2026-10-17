use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const DIALOG_TIMEOUT_SECS: u64 = 60;

/// Displays a native OS dialog asking the user whether to grant access to secrets.
/// Includes a 60-second timeout to prevent locking host IDEs/clients indefinitely.
pub fn ask_user_permission(command_name: &str, secrets: &[String]) -> bool {
    let secret_list = secrets.join(", ");
    let message = format!(
        "MCP Server is requesting access to environment secrets:\n\n\
        Command: {}\n\
        Requested Secrets: [{}]\n\n\
        Do you allow this MCP server to access these secrets?\n\
        (This permission will be remembered for future runs)",
        command_name, secret_list
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
